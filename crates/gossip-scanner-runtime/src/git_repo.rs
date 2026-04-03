//! Git-repository runtime boundary for local repository scanning.
//!
//! This module implements the Git-family scan path: given a validated repository
//! root and a [`GitScanConfig`], it builds a detection engine, spawns a scoped
//! event-forwarding thread, runs the `scanner_git` scan pipeline, and translates
//! the resulting metrics into the crate-level [`ScanReport`].
//!
//! # Threading model
//!
//! `scan_local_repo` uses [`std::thread::scope`] to spawn a single event
//! forwarder thread. The scan itself runs on the calling thread. Events flow
//! through a bounded `sync_channel` (capacity `EVENT_CHANNEL_CAP`) from
//! the scan thread to the forwarder, which replays them into the caller's
//! [`GitEventOutput`] sink. The channel is dropped after the scan completes,
//! which signals the forwarder to flush and exit.
//!
//! # Watermark and seen-OID stores
//!
//! Local scans always perform a full scan with no incremental watermarks.
//! `EmptyWatermarkStore` returns `None` for every ref, and `NeverSeenStore`
//! treats every OID as unseen. Incremental behavior is reserved for the
//! distributed runtime path.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

use anyhow::anyhow;
use gossip_contracts::connector::ToxicDigest;
use gossip_contracts::connector::git::{
    GitMirrorManager, GitRefSelection, GitRepoDiscoverySource, GitRepoExecutor,
};
use scanner_git::{
    GitEventOutput, GitScanConfig as RuntimeGitScanConfig, GitScanError, GitScanResult,
    NativeRefResolver, NeverSeenStore, OidBytes, RefWatermarkStore, RepoOpenError, StartSetConfig,
    run_git_scan,
};

use crate::{
    AssignmentOutcome, CancellationToken, ChannelEventOutput, EVENT_CHANNEL_CAP, GitDebugLevel,
    GitScanConfig, ScanReport, ScanRuntimeError, build_runtime_engine, forward_git_events,
    join_scoped,
};

/// Marker type for the Git-repository source family.
///
/// Provides the trait-dispatched entry points for discovery and mirrored-repo
/// execution. These paths are placeholders; the primary scan path for local
/// repositories is the crate-internal `scan_local_repo` function.
#[derive(Debug, Default)]
pub struct GitRepoRuntime;

impl GitRepoRuntime {
    /// Execute one discovery source (not yet implemented).
    ///
    /// Discovery sources enumerate repositories from a remote API. This path
    /// always returns an error until connector-level repository enumeration is
    /// wired in.
    pub fn execute_discovery<D: GitRepoDiscoverySource>(
        _discovery: &mut D,
    ) -> Result<ScanReport, ScanRuntimeError> {
        Err(ScanRuntimeError::Driver(anyhow!(
            "git-repo discovery runtime path for source '{}' is not implemented yet",
            std::any::type_name::<D>()
        )))
    }

    /// Execute one mirrored repository.
    ///
    /// [`crate::git_mirror::LocalMirrorManager`] provides the concrete mirror
    /// lifecycle implementation, and [`crate::git_executor::ScannerGitExecutor`]
    /// provides the per-repository execution adapter. This entrypoint still
    /// returns an error because higher-level runtime orchestration has not yet
    /// wired mirror acquisition, selection, and execution together.
    pub fn execute_repo<M: GitMirrorManager, E: GitRepoExecutor>(
        _mirrors: &mut M,
        _executor: &mut E,
    ) -> Result<ScanReport, ScanRuntimeError> {
        Err(ScanRuntimeError::Driver(anyhow!(
            "git-repo execution runtime path for executor '{}' requires mirror and selection context",
            std::any::type_name::<E>()
        )))
    }
}

/// Shared low-level `scanner-git` execution output.
pub(crate) struct GitRunExecution {
    pub(crate) result: GitScanResult,
    pub(crate) scan_elapsed: Duration,
}

/// Run a full Git object scan against a local repository.
///
/// This is the primary scan path for Git sources. It builds a detection engine,
/// opens the repository at `canonical_repo`, and scans the configured
/// start-set coverage described by [`GitScanConfig::ref_selection`].
///
/// # Event forwarding
///
/// A scoped thread drains events from the scan into `out`. The event channel
/// is explicitly dropped after `run_git_scan` returns so the forwarder observes
/// a clean EOF rather than blocking indefinitely.
///
/// # Errors
///
/// Returns [`ScanRuntimeError::Driver`] if the underlying `run_git_scan` call
/// fails, or propagates engine-construction errors from [`build_runtime_engine`].
pub(crate) fn scan_local_repo(
    config: &GitScanConfig,
    canonical_repo: PathBuf,
    out: &dyn GitEventOutput,
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

    let (report, debug_output) = std::thread::scope(|scope| -> Result<_, ScanRuntimeError> {
        let (event_tx, event_rx) = sync_channel(EVENT_CHANNEL_CAP);
        let event_forwarder = scope.spawn(move || forward_git_events(out, event_rx));

        let git_sink: Arc<dyn scanner_git::EventSink> =
            Arc::new(ChannelEventOutput::new(event_tx.clone()));
        let git_cfg = build_git_scan_config(config)?;
        let execution =
            run_runtime_git_scan(&canonical_repo, engine, &git_cfg, git_sink).map_err(|error| {
                ScanRuntimeError::Driver(anyhow!(
                    "git scan failed for '{}': {error}",
                    digest_repo_path(&canonical_repo)
                ))
            })?;

        // Close the sender before joining so the forwarder thread sees EOF.
        drop(event_tx);
        join_scoped(event_forwarder, "git event forwarder thread")
            .map_err(ScanRuntimeError::Driver)?;

        let debug_output = format_git_debug_output(&execution.result.0, config.debug_level);
        Ok((
            git_report_to_scan_report(execution.result, execution.scan_elapsed),
            debug_output,
        ))
    })?;

    Ok(AssignmentOutcome {
        report,
        checkpoint_hint: None,
        debug_output,
    })
}

/// Produce a [`ToxicDigest`] from a repo path for log-safe error messages.
///
/// Uses `OsStr::as_encoded_bytes` on all platforms for consistency with
/// `NormalizedLocalRepoIdentity`'s key derivation, so the digest
/// correlates with the authoritative repo identity key.
pub(crate) fn digest_repo_path(p: &std::path::Path) -> ToxicDigest {
    ToxicDigest::of_bytes(p.as_os_str().as_encoded_bytes())
}

/// Convert a MiB value to a byte count, rejecting zero and overflow.
pub(crate) fn mebibytes_to_u32_bytes(
    value_mb: u32,
    label: &'static str,
) -> Result<u32, ScanRuntimeError> {
    const MIB: u32 = 1024 * 1024;

    if value_mb == 0 {
        return Err(ScanRuntimeError::ConnectorInput(
            gossip_contracts::connector::ConnectorInputError::ZeroBudget { field: label },
        ));
    }
    value_mb.checked_mul(MIB).ok_or_else(|| {
        ScanRuntimeError::Driver(anyhow!(
            "{label} value {value_mb} MiB overflows u32 byte count"
        ))
    })
}

/// Convert a MiB value to a platform-sized byte count, rejecting zero and overflow.
pub(crate) fn mebibytes_to_usize_bytes(
    value_mb: u32,
    label: &'static str,
) -> Result<usize, ScanRuntimeError> {
    usize::try_from(mebibytes_to_u32_bytes(value_mb, label)?).map_err(|_| {
        ScanRuntimeError::Driver(anyhow!(
            "{label} value {value_mb} MiB exceeds platform usize"
        ))
    })
}

/// Translate the crate-level [`GitScanConfig`] into the lower-level
/// [`RuntimeGitScanConfig`] consumed by `scanner_git::run_git_scan`.
///
/// MiB-denominated size overrides are converted to byte counts with overflow
/// checking. Zero-valued budgets are rejected as configuration errors.
fn build_git_scan_config(config: &GitScanConfig) -> Result<RuntimeGitScanConfig, ScanRuntimeError> {
    let mut git_cfg = RuntimeGitScanConfig {
        repo_id: config.repo_id,
        scan_mode: config.scan_mode,
        merge_diff_mode: config.merge_mode,
        pack_exec_workers: config.workers.max(1),
        enrich_identities: config.enrich_identities,
        // Translate the lowered ref-selection policy into the scanner-level
        // start-set config. By this point, explicit-commit selections have
        // already been lowered to ExplicitRefs with a synthetic ref name.
        start_set: start_set_from_ref_selection(&config.ref_selection),
        ..RuntimeGitScanConfig::default()
    };
    git_cfg.engine_adapter.scan_binary = config.scan_binary;

    if let Some(value_mb) = config.tree_delta_cache_mb {
        git_cfg.tree_diff.max_tree_delta_cache_bytes =
            mebibytes_to_u32_bytes(value_mb, "git_tree_delta_cache_mb")?;
    }
    if let Some(value_mb) = config.engine_chunk_mb {
        git_cfg.engine_adapter.chunk_bytes =
            mebibytes_to_usize_bytes(value_mb, "git_engine_chunk_mb")?;
    }

    Ok(git_cfg)
}

/// Execute the shared `scanner-git` runner setup against `canonical_repo`.
pub(crate) fn run_runtime_git_scan(
    canonical_repo: &Path,
    engine: Arc<scanner_engine::Engine>,
    git_cfg: &RuntimeGitScanConfig,
    git_sink: Arc<dyn scanner_git::EventSink>,
) -> Result<GitRunExecution, GitScanError> {
    let resolver = NativeRefResolver::new(git_cfg.start_set.clone());
    let watermarks = EmptyWatermarkStore;
    let seen = NeverSeenStore;

    let scan_start = std::time::Instant::now();
    let result = run_git_scan(
        canonical_repo,
        engine,
        &resolver,
        &seen,
        &watermarks,
        None,
        git_cfg,
        git_sink,
    )?;

    Ok(GitRunExecution {
        result,
        scan_elapsed: scan_start.elapsed(),
    })
}

/// Map a contract-level [`GitRefSelection`] to the scanner-level
/// [`StartSetConfig`] consumed by [`NativeRefResolver`].
///
/// This is a mechanical translation — each `GitRefSelection` variant maps 1:1
/// to a `StartSetConfig` variant. The function exists to isolate the runtime
/// from the scanner crate's internal config types. Explicit-commit selections
/// should be lowered to `ExplicitRefs` (via
/// [`materialize_synthetic_commit_ref`](scanner_git::materialize_synthetic_commit_ref))
/// before reaching this function; `GitRefSelection` has no commit variant.
pub(crate) fn start_set_from_ref_selection(selection: &GitRefSelection) -> StartSetConfig {
    match selection {
        GitRefSelection::DefaultBranchOnly => StartSetConfig::DefaultBranchOnly,
        GitRefSelection::AllRemoteBranches { remote } => StartSetConfig::AllRemoteBranches {
            remote: remote.clone(),
        },
        GitRefSelection::BranchesAndTags {
            include_remote_branches,
            remote,
        } => StartSetConfig::BranchesAndTags {
            include_remote_branches: *include_remote_branches,
            remote: remote.clone(),
        },
        GitRefSelection::ExplicitRefs { refs } => {
            StartSetConfig::ExplicitRefs { refs: refs.clone() }
        }
    }
}

/// Resolve the authoritative scan duration in nanoseconds.
///
/// Prefers the scanner's own stage-level `scan` timing when available (> 0).
/// Falls back to `wall_elapsed` (wall-clock measurement from the runtime)
/// when the scanner did not record stage timing, which can happen with
/// certain scan modes that bypass the stage-nanos pipeline.
pub(crate) fn resolve_scan_ns(
    stage_nanos: &scanner_git::GitScanStageNanos,
    wall_elapsed: std::time::Duration,
) -> u64 {
    if stage_nanos.scan > 0 {
        stage_nanos.scan
    } else {
        u64::try_from(wall_elapsed.as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Map `scanner_git` metrics into the crate-level [`ScanReport`].
///
/// Prefers the scanner's own stage-level `scan` timing when available. Falls
/// back to `scan_elapsed` (wall-clock measurement from the runtime) when the
/// scanner did not record stage timing, which can happen with certain scan
/// modes that bypass the stage-nanos pipeline.
///
/// Git scans have no persistence layer, so `dropped_findings`,
/// `persist_emit_failures`, `persist_incomplete`, and `persist_ns` are zeroed.
fn git_report_to_scan_report(
    result: GitScanResult,
    scan_elapsed: std::time::Duration,
) -> ScanReport {
    let report = result.0;
    let metrics = report.common_metrics;
    let scan_ns = resolve_scan_ns(&report.stage_nanos, scan_elapsed);

    ScanReport {
        items_scanned: metrics.objects_scanned,
        items_deferred: 0,
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

/// Render human-readable debug diagnostics from the Git scan report.
///
/// Output format is `key=value\n` pairs suitable for stderr or log ingestion.
///
/// - [`GitDebugLevel::Off`] produces `None`.
/// - [`GitDebugLevel::Stats`] emits aggregate counters and stage timings.
/// - [`GitDebugLevel::Perf`] additionally includes per-pack-exec cache and
///   resolve latency breakdowns.
pub(crate) fn format_git_debug_output(
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

    let sn = &report.stage_nanos;
    let stages: &[(&str, u64)] = &[
        ("stage.tree_diff.nanos", sn.tree_diff),
        ("stage.commit_plan.nanos", sn.commit_plan),
        ("stage.blob_intro.nanos", sn.blob_intro),
        ("stage.spill.nanos", sn.spill),
        ("stage.pack_collect.nanos", sn.pack_collect),
        ("stage.mapping.nanos", sn.mapping),
        ("stage.pack_plan.nanos", sn.pack_plan),
        ("stage.pack_exec.nanos", sn.pack_exec),
        ("stage.loose_scan.nanos", sn.loose_scan),
        ("stage.scan.nanos", sn.scan),
    ];
    if stages.iter().any(|&(_, v)| v > 0) {
        for &(key, value) in stages {
            push_line(&mut out, key, value);
        }
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

/// No-op watermark store that always returns `None` for every ref.
///
/// Forces a full scan from each ref tip, with no incremental skipping.
/// Appropriate for local / CLI scans where no persistent watermark state
/// is maintained between runs.
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
    use crate::GitScanConfig;
    use gossip_contracts::connector::git::GitRefSelection;

    /// Zero-valued `tree_delta_cache_mb` produces a `ZeroBudget` error.
    #[test]
    fn build_git_scan_config_rejects_zero_tree_delta_cache() {
        let cfg = GitScanConfig::new("/tmp").with_tree_delta_cache_mb(Some(0));
        let err = build_git_scan_config(&cfg).expect_err("zero tree_delta_cache_mb");
        assert!(
            matches!(err, ScanRuntimeError::ConnectorInput(_)),
            "expected ConnectorInput(ZeroBudget), got: {err:?}"
        );
    }

    /// `tree_delta_cache_mb` that overflows u32 byte count produces a Driver error.
    #[test]
    fn build_git_scan_config_rejects_overflow_tree_delta_cache() {
        let cfg = GitScanConfig::new("/tmp").with_tree_delta_cache_mb(Some(4096));
        let err = build_git_scan_config(&cfg).expect_err("overflow tree_delta_cache_mb");
        assert!(
            matches!(err, ScanRuntimeError::Driver(_)),
            "expected Driver (overflow), got: {err:?}"
        );
    }

    /// Zero-valued `engine_chunk_mb` produces a `ZeroBudget` error.
    #[test]
    fn build_git_scan_config_rejects_zero_engine_chunk() {
        let cfg = GitScanConfig::new("/tmp").with_engine_chunk_mb(Some(0));
        let err = build_git_scan_config(&cfg).expect_err("zero engine_chunk_mb");
        assert!(
            matches!(err, ScanRuntimeError::ConnectorInput(_)),
            "expected ConnectorInput(ZeroBudget), got: {err:?}"
        );
    }

    /// `engine_chunk_mb` that overflows u32 byte count produces a Driver error.
    #[test]
    fn build_git_scan_config_rejects_overflow_engine_chunk() {
        let cfg = GitScanConfig::new("/tmp").with_engine_chunk_mb(Some(4096));
        let err = build_git_scan_config(&cfg).expect_err("overflow engine_chunk_mb");
        assert!(
            matches!(err, ScanRuntimeError::Driver(_)),
            "expected Driver (overflow), got: {err:?}"
        );
    }

    #[test]
    fn explicit_refs_selection_maps_to_start_set_config() {
        let refs = vec![b"refs/gossip/scan-targets/commits/sha1/abc".to_vec()];
        let cfg = GitScanConfig::new("/tmp")
            .with_ref_selection(GitRefSelection::ExplicitRefs { refs: refs.clone() });

        let built = build_git_scan_config(&cfg).expect("build runtime git config");
        assert_eq!(built.start_set, StartSetConfig::ExplicitRefs { refs });
    }

    /// Default `GitRefSelection` (i.e. `DefaultBranchOnly`) maps to
    /// `StartSetConfig::DefaultBranchOnly`.
    #[test]
    fn build_git_scan_config_uses_default_branch_only_start_set() {
        let cfg = GitScanConfig::new("/tmp");

        let built = build_git_scan_config(&cfg).expect("build config");
        assert_eq!(built.start_set, StartSetConfig::DefaultBranchOnly);
    }

    /// `AllRemoteBranches` with a specific remote propagates the remote filter.
    #[test]
    fn build_git_scan_config_uses_all_remote_branches_start_set() {
        let cfg =
            GitScanConfig::new("/tmp").with_ref_selection(GitRefSelection::AllRemoteBranches {
                remote: Some(b"upstream".to_vec()),
            });

        let built = build_git_scan_config(&cfg).expect("build config");
        assert_eq!(
            built.start_set,
            StartSetConfig::AllRemoteBranches {
                remote: Some(b"upstream".to_vec()),
            }
        );
    }

    /// `BranchesAndTags` with remote branches enabled and no remote filter
    /// propagates both fields.
    #[test]
    fn build_git_scan_config_uses_branches_and_tags_start_set() {
        let cfg = GitScanConfig::new("/tmp").with_ref_selection(GitRefSelection::BranchesAndTags {
            include_remote_branches: true,
            remote: None,
        });

        let built = build_git_scan_config(&cfg).expect("build config");
        assert_eq!(
            built.start_set,
            StartSetConfig::BranchesAndTags {
                include_remote_branches: true,
                remote: None,
            }
        );
    }
}
