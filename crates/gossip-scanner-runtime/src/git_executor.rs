//! Contract-level adapter for mirror-backed Git repository execution.
//!
//! This module bridges the repo-family contracts in `gossip-contracts` to the
//! existing `scanner-git` runtime by implementing [`GitRepoExecutor`] for a
//! concrete executor that runs against a prepared [`LocalMirror`].
//!
//! The adapter reuses the lower-level runner setup in [`crate::git_repo`]
//! rather than maintaining a second `run_git_scan` wrapper. It translates
//! contract-level selection and limit types into `scanner_git::GitScanConfig`,
//! forwards events through the same bounded channel + scoped-thread path as the
//! local runtime, and classifies `scanner-git` failures onto the existing
//! [`GitRunError`] boundary.

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;

use gossip_contracts::connector::git::{
    GitDebugLevel, GitExecutionLimits, GitMergeStrategy, GitRepoExecutor, GitRunError,
    GitRunOutcome, GitScanMode as ContractGitScanMode, GitSelection, LocalMirror,
};
use scanner_engine::Engine;
use scanner_git::{
    ArtifactAcquireError, GitEventOutput, GitScanConfig as ScannerGitScanConfig, GitScanError,
    GitScanMode as ScannerGitScanMode, MergeDiffMode,
};

use crate::git_repo::{
    GitRunExecution, digest_repo_path, format_git_debug_output, mebibytes_to_u32_bytes,
    mebibytes_to_usize_bytes, run_runtime_git_scan, start_set_from_ref_selection,
};
use crate::{
    ChannelEventOutput, EVENT_CHANNEL_CAP, GitScanConfig as RuntimeGitScanConfig, ScanRuntimeError,
    available_workers, build_runtime_engine, forward_git_events, join_scoped,
};

/// Concrete `scanner-git` adapter for [`GitRepoExecutor`].
///
/// The executor owns a pre-built detection engine so expensive rule
/// compilation is amortized across repository runs. Per-run selection and
/// limit choices still come from the contract-level `run_repo` call.
pub struct ScannerGitExecutor {
    repo_id: u64,
    engine: Arc<Engine>,
    out: Arc<dyn GitEventOutput + Send + Sync>,
}

#[derive(Debug)]
struct ExecutorGitScanConfig {
    git_cfg: ScannerGitScanConfig,
    debug_level: GitDebugLevel,
}

impl ScannerGitExecutor {
    /// Construct a repo executor from a pre-built engine and event sink.
    #[must_use]
    pub fn new(
        repo_id: u64,
        engine: Arc<Engine>,
        out: Arc<dyn GitEventOutput + Send + Sync>,
    ) -> Self {
        Self {
            repo_id,
            engine,
            out,
        }
    }

    /// Build an executor from the runtime's engine-construction settings.
    ///
    /// The runtime config contributes `repo_id` plus the rule, transform, and
    /// anchor settings needed to construct the shared engine. Selection and
    /// execution limits continue to flow through [`GitRepoExecutor::run_repo`].
    pub fn from_runtime_config(
        config: &RuntimeGitScanConfig,
        out: Arc<dyn GitEventOutput + Send + Sync>,
    ) -> Result<Self, ScanRuntimeError> {
        let engine = build_runtime_engine(
            config.rules_file.as_deref(),
            &config.transform_filter,
            config.decode_depth,
            config.anchor_mode,
        )?;
        Ok(Self::new(config.repo_id, engine, out))
    }

    fn run_repo_with<R>(
        &self,
        mirror: &LocalMirror,
        selection: &GitSelection,
        limits: GitExecutionLimits,
        run_scan: R,
    ) -> Result<GitRunOutcome, GitRunError>
    where
        R: FnOnce(
            &Path,
            Arc<Engine>,
            &ScannerGitScanConfig,
            Arc<dyn scanner_git::EventSink>,
        ) -> Result<GitRunExecution, GitScanError>,
    {
        if mirror.path().as_os_str().is_empty() {
            return Err(GitRunError::permanent("git mirror path must not be empty"));
        }

        let ExecutorGitScanConfig {
            git_cfg,
            debug_level,
        } = build_git_scan_config(self.repo_id, selection, limits)?;

        std::thread::scope(|scope| {
            let (event_tx, event_rx) = sync_channel(EVENT_CHANNEL_CAP);
            let out = Arc::clone(&self.out);
            let event_forwarder = scope.spawn(move || forward_git_events(out.as_ref(), event_rx));

            let git_sink: Arc<dyn scanner_git::EventSink> =
                Arc::new(ChannelEventOutput::new(event_tx.clone()));
            let execution = run_scan(mirror.path(), Arc::clone(&self.engine), &git_cfg, git_sink);

            drop(event_tx);
            join_scoped(event_forwarder, "git event forwarder thread").map_err(|error| {
                GitRunError::retryable(format!(
                    "git event forwarder failed for '{}': {error}",
                    digest_repo_path(mirror.path())
                ))
            })?;

            let execution = execution.map_err(|error| classify_scan_error(error, mirror.path()))?;
            maybe_log_debug_output(mirror.path(), debug_level, &execution.result.0);
            Ok(git_run_outcome(execution))
        })
    }
}

impl GitRepoExecutor for ScannerGitExecutor {
    /// Execute one mirror-backed Git scan.
    ///
    /// `mirror.path()` is treated as the authoritative repo root, and the
    /// contract-level selection is translated directly into the scanner's
    /// start-set / mode configuration without rewriting ref identity.
    ///
    /// Retryable failures remain retryable [`GitRunError`] values, while
    /// invalid repo-open or selection inputs surface as permanent errors.
    fn run_repo(
        &mut self,
        mirror: &LocalMirror,
        selection: &GitSelection,
        limits: GitExecutionLimits,
    ) -> Result<GitRunOutcome, GitRunError> {
        self.run_repo_with(mirror, selection, limits, run_runtime_git_scan)
    }
}

/// Map the contract scan mode onto the scanner-git scan mode.
fn map_scan_mode(mode: ContractGitScanMode) -> ScannerGitScanMode {
    match mode {
        ContractGitScanMode::DiffHistory => ScannerGitScanMode::DiffHistory,
        ContractGitScanMode::OdbBlobFast => ScannerGitScanMode::OdbBlobFast,
    }
}

/// Map the contract merge strategy onto the scanner-git merge mode.
fn map_merge_strategy(strategy: GitMergeStrategy) -> MergeDiffMode {
    match strategy {
        GitMergeStrategy::AllParents => MergeDiffMode::AllParents,
        GitMergeStrategy::FirstParentOnly => MergeDiffMode::FirstParentOnly,
    }
}

fn build_git_scan_config(
    repo_id: u64,
    selection: &GitSelection,
    limits: GitExecutionLimits,
) -> Result<ExecutorGitScanConfig, GitRunError> {
    let mut git_cfg = ScannerGitScanConfig {
        repo_id,
        scan_mode: map_scan_mode(selection.scan_mode()),
        merge_diff_mode: map_merge_strategy(selection.merge_strategy()),
        pack_exec_workers: limits
            .pack_exec_workers()
            .unwrap_or_else(available_workers)
            .max(1),
        enrich_identities: limits.enrich_identities(),
        start_set: start_set_from_ref_selection(selection.refs()),
        ..ScannerGitScanConfig::default()
    };
    git_cfg.engine_adapter.scan_binary = limits.scan_binary();

    if let Some(value_mb) = limits.tree_delta_cache_mb() {
        git_cfg.tree_diff.max_tree_delta_cache_bytes =
            mebibytes_to_u32_bytes(value_mb, "git_tree_delta_cache_mb")
                .map_err(|error| GitRunError::permanent(error.to_string()))?;
    }
    if let Some(value_mb) = limits.engine_chunk_mb() {
        git_cfg.engine_adapter.chunk_bytes =
            mebibytes_to_usize_bytes(value_mb, "git_engine_chunk_mb")
                .map_err(|error| GitRunError::permanent(error.to_string()))?;
    }

    Ok(ExecutorGitScanConfig {
        git_cfg,
        debug_level: limits.debug_level(),
    })
}

fn maybe_log_debug_output(
    mirror_path: &Path,
    debug_level: GitDebugLevel,
    report: &scanner_git::GitScanReport,
) {
    if let Some(debug_output) = format_git_debug_output(report, debug_level) {
        tracing::debug!(
            repo = %digest_repo_path(mirror_path),
            diagnostics = %debug_output,
            "git repo execution diagnostics"
        );
    }
}

/// Classify one scanner-git failure onto the repo-executor error boundary.
///
/// Repo-open and selection-shape failures are treated as permanent input or
/// configuration errors. Concurrent maintenance remains retryable, and the
/// remaining pipeline-stage failures stay retryable so callers can recover by
/// refreshing the mirror or retrying later.
fn classify_scan_error(err: GitScanError, mirror_path: &Path) -> GitRunError {
    let repo = digest_repo_path(mirror_path);
    match err {
        GitScanError::ConcurrentMaintenance
        | GitScanError::ArtifactAcquire(ArtifactAcquireError::ConcurrentMaintenance) => {
            GitRunError::concurrent_maintenance()
        }
        GitScanError::RepoOpen(error) => {
            GitRunError::permanent(format!("git repo execution failed for '{repo}': {error}"))
        }
        GitScanError::UnsupportedMode(error) => {
            GitRunError::permanent(format!("git repo execution failed for '{repo}': {error}"))
        }
        GitScanError::ResourceLimit(error) => GitRunError::permanent(format!(
            "git repo execution failed for '{repo}': resource limit exceeded: {error}"
        )),
        GitScanError::ArtifactAcquire(ArtifactAcquireError::EmptyStartSetWithRefs) => {
            GitRunError::permanent(format!(
                "git repo execution failed for '{repo}': empty start set while repository refs exist (refusing silent no-op scan)"
            ))
        }
        other => GitRunError::retryable(format!("git repo execution failed for '{repo}': {other}")),
    }
}

fn git_run_outcome(execution: GitRunExecution) -> GitRunOutcome {
    let report = execution.result.0;
    let metrics = report.common_metrics;
    let scan_ns = if report.stage_nanos.scan > 0 {
        report.stage_nanos.scan
    } else {
        u64::try_from(execution.scan_elapsed.as_nanos()).unwrap_or(u64::MAX)
    };

    GitRunOutcome {
        commit_count: u64::try_from(report.commit_count).unwrap_or(u64::MAX),
        objects_scanned: metrics.objects_scanned,
        bytes_scanned: metrics.bytes_scanned,
        chunks_scanned: metrics.chunks_scanned,
        findings_emitted: metrics.findings_emitted,
        errors: metrics.errors,
        scan_ns,
        persist_ns: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::num::{NonZeroU32, NonZeroUsize};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use gossip_contracts::connector::ErrorClass;
    use gossip_contracts::connector::git::{GitRefSelection, GitRepoExecutor};
    use rstest::rstest;
    use scanner_git::{NullEventSink, RepoOpenError};

    use super::*;
    use crate::{AnchorMode, TransformFilter};

    fn test_engine() -> Arc<Engine> {
        build_runtime_engine(None, &TransformFilter::All, None, AnchorMode::Manual)
            .expect("runtime engine")
    }

    fn test_executor() -> ScannerGitExecutor {
        ScannerGitExecutor::new(7, test_engine(), Arc::new(NullEventSink))
    }

    #[rstest]
    #[case(
        GitRefSelection::DefaultBranchOnly,
        scanner_git::StartSetConfig::DefaultBranchOnly
    )]
    #[case(
        GitRefSelection::AllRemoteBranches {
            remote: Some(b"origin".to_vec()),
        },
        scanner_git::StartSetConfig::AllRemoteBranches {
            remote: Some(b"origin".to_vec()),
        }
    )]
    #[case(
        GitRefSelection::BranchesAndTags {
            include_remote_branches: true,
            remote: Some(b"upstream".to_vec()),
        },
        scanner_git::StartSetConfig::BranchesAndTags {
            include_remote_branches: true,
            remote: Some(b"upstream".to_vec()),
        }
    )]
    #[case(
        GitRefSelection::ExplicitRefs {
            refs: vec![b"refs/synth/abc".to_vec()],
        },
        scanner_git::StartSetConfig::ExplicitRefs {
            refs: vec![b"refs/synth/abc".to_vec()],
        }
    )]
    fn ref_selection_variants_map_without_rewriting_identity(
        #[case] ref_selection: GitRefSelection,
        #[case] expected: scanner_git::StartSetConfig,
    ) {
        let selection = GitSelection::new(
            ref_selection,
            ContractGitScanMode::OdbBlobFast,
            GitMergeStrategy::AllParents,
        );

        let built = build_git_scan_config(9, &selection, GitExecutionLimits::default())
            .expect("executor git scan config");
        assert_eq!(built.git_cfg.start_set, expected);
    }

    #[rstest]
    #[case(ContractGitScanMode::DiffHistory, ScannerGitScanMode::DiffHistory)]
    #[case(ContractGitScanMode::OdbBlobFast, ScannerGitScanMode::OdbBlobFast)]
    fn scan_mode_mapping_is_exhaustive(
        #[case] mode: ContractGitScanMode,
        #[case] expected: ScannerGitScanMode,
    ) {
        assert_eq!(map_scan_mode(mode), expected);
    }

    #[rstest]
    #[case(GitMergeStrategy::AllParents, MergeDiffMode::AllParents)]
    #[case(GitMergeStrategy::FirstParentOnly, MergeDiffMode::FirstParentOnly)]
    fn merge_strategy_mapping_is_exhaustive(
        #[case] strategy: GitMergeStrategy,
        #[case] expected: MergeDiffMode,
    ) {
        assert_eq!(map_merge_strategy(strategy), expected);
    }

    #[test]
    fn execution_limits_map_to_scanner_git_config() {
        let limits = GitExecutionLimits::default()
            .with_pack_exec_workers(NonZeroUsize::new(5).expect("non-zero"))
            .with_scan_binary(true)
            .with_enrich_identities(true)
            .with_debug_level(GitDebugLevel::Perf)
            .with_tree_delta_cache_mb(NonZeroU32::new(3).expect("non-zero"))
            .with_engine_chunk_mb(NonZeroU32::new(2).expect("non-zero"));
        let selection = GitSelection::new(
            GitRefSelection::ExplicitRefs {
                refs: vec![b"refs/heads/main".to_vec()],
            },
            ContractGitScanMode::DiffHistory,
            GitMergeStrategy::FirstParentOnly,
        );

        let built = build_git_scan_config(42, &selection, limits).expect("executor config");
        assert_eq!(built.git_cfg.repo_id, 42);
        assert_eq!(built.git_cfg.scan_mode, ScannerGitScanMode::DiffHistory);
        assert_eq!(
            built.git_cfg.merge_diff_mode,
            MergeDiffMode::FirstParentOnly
        );
        assert_eq!(built.git_cfg.pack_exec_workers, 5);
        assert!(built.git_cfg.engine_adapter.scan_binary);
        assert!(built.git_cfg.enrich_identities);
        assert_eq!(
            built.git_cfg.tree_diff.max_tree_delta_cache_bytes,
            3 * 1024 * 1024
        );
        assert_eq!(built.git_cfg.engine_adapter.chunk_bytes, 2 * 1024 * 1024);
        assert_eq!(built.debug_level, GitDebugLevel::Perf);
    }

    #[test]
    fn mib_overflow_is_rejected_as_permanent_error() {
        let limits = GitExecutionLimits::default()
            .with_tree_delta_cache_mb(NonZeroU32::new(u32::MAX).expect("non-zero"));

        let err = build_git_scan_config(1, &GitSelection::default(), limits)
            .expect_err("overflow should fail");
        assert_eq!(err.class(), ErrorClass::Permanent);
    }

    #[test]
    fn empty_mirror_path_is_rejected_before_scan() {
        let mut executor = test_executor();
        let mirror = LocalMirror::new("");
        let err = executor
            .run_repo(
                &mirror,
                &GitSelection::default(),
                GitExecutionLimits::default(),
            )
            .expect_err("empty mirror path should fail");

        assert_eq!(err.class(), ErrorClass::Permanent);
        assert!(err.message().contains("must not be empty"));
    }

    #[test]
    fn executor_runs_against_the_prepared_mirror_path() {
        let executor = test_executor();
        let mirror = LocalMirror::new("/tmp/prepared-mirror.git");
        let captured = Arc::new(Mutex::new(None::<PathBuf>));
        let captured_path = Arc::clone(&captured);

        let err = executor
            .run_repo_with(
                &mirror,
                &GitSelection::default(),
                GitExecutionLimits::default(),
                move |path, _engine, _cfg, _sink| {
                    *captured_path.lock().expect("capture mutex") = Some(path.to_path_buf());
                    Err(GitScanError::ConcurrentMaintenance)
                },
            )
            .expect_err("stubbed runner should fail");

        assert_eq!(err.class(), ErrorClass::Retryable);
        assert_eq!(
            captured.lock().expect("capture mutex").as_deref(),
            Some(mirror.path())
        );
    }

    #[rstest]
    #[case(GitScanError::ConcurrentMaintenance, ErrorClass::Retryable)]
    #[case(
        GitScanError::ArtifactAcquire(ArtifactAcquireError::ConcurrentMaintenance),
        ErrorClass::Retryable
    )]
    #[case(
        GitScanError::RepoOpen(RepoOpenError::NotARepository),
        ErrorClass::Permanent
    )]
    #[case(
        GitScanError::UnsupportedMode(ScannerGitScanMode::DiffHistory),
        ErrorClass::Permanent
    )]
    #[case(
        GitScanError::ResourceLimit("pack mmap budget".to_owned()),
        ErrorClass::Permanent
    )]
    #[case(
        GitScanError::ArtifactAcquire(ArtifactAcquireError::EmptyStartSetWithRefs),
        ErrorClass::Permanent
    )]
    #[case(
        GitScanError::Io(std::io::Error::other("temporary I/O failure")),
        ErrorClass::Retryable
    )]
    fn scan_error_classification_preserves_retry_posture(
        #[case] error: GitScanError,
        #[case] expected: ErrorClass,
    ) {
        let classified = classify_scan_error(error, Path::new("/tmp/mirror.git"));
        assert_eq!(classified.class(), expected);
    }

    #[test]
    fn executor_implements_contract_and_send_bounds() {
        fn assert_send<T: Send>() {}
        fn assert_executor<T: GitRepoExecutor>() {}

        assert_send::<ScannerGitExecutor>();
        assert_executor::<ScannerGitExecutor>();
    }
}
