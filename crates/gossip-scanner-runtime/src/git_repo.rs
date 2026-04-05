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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::time::Duration;

use anyhow::anyhow;
use gossip_contracts::connector::git::{
    GitRefSelection, GitRepoDiscoverySource, GitRepoTarget, GitSelection, LocalMirror,
};
use gossip_contracts::connector::{Budgets, Cursor, PageBuf, PageState, ToxicDigest};
use gossip_contracts::coordination::ShardSpec;
use gossip_contracts::identity::RuleFingerprint;
use gossip_contracts::persistence::WriteContext;
use gossip_orchestrator::{GitSelectionLoweringError, GitShardPayload};
use scanner_git::{
    FinalizeOutcome, GitEventOutput, GitScanConfig as RuntimeGitScanConfig, GitScanError,
    GitScanResult, NativeRefResolver, NeverSeenStore, PersistenceStore, RefWatermark,
    RefWatermarkStore, RepoOpenError, RepoOpenLimits, SeenBlobStore, StartSetConfig, run_git_scan,
};

use crate::git_executor::{ScannerGitExecutor, map_merge_strategy, map_scan_mode};
use crate::git_persistence::{GitPersistenceAdapter, GitPersistenceBackend};
use crate::{
    AssignmentOutcome, CancellationToken, ChannelEventOutput, EVENT_CHANNEL_CAP, GitDebugLevel,
    GitScanConfig, ScanReport, ScanRuntimeError, build_runtime_engine, forward_git_events,
    join_scoped,
};

/// Marker type for the Git-repository source family.
///
/// Provides the trait-dispatched entry points for one-target repo discovery
/// and prepared-mirror execution. The local direct-scan path remains the
/// crate-internal `scan_local_repo` function.
#[derive(Debug, Default)]
pub struct GitRepoRuntime;

/// Aggregate outcome from executing one mirror-backed Git repository scan.
///
/// Bundles the scan metrics, the persistence adapter (for downstream
/// checkpoint construction), and the scanner's finalize outcome (complete vs.
/// partial). Produced by [`GitRepoRuntime::execute_repo`] and consumed by
/// the distributed Git worker loop. The caller builds the checkpoint input
/// after obtaining durable findings and done-ledger receipts.
#[must_use]
pub(crate) struct GitRepoExecutionOutcome<B> {
    /// Aggregate scan metrics (objects, bytes, findings, errors) translated
    /// into the crate-level report format.
    pub(crate) report: ScanReport,
    /// The persistence adapter that managed watermarks and seen-bitmaps
    /// during the scan. Retained so the caller can build the checkpoint
    /// input with the real findings and done-ledger receipts.
    pub(crate) persistence: GitPersistenceAdapter<B>,
    /// The write context used during execution, needed for checkpoint
    /// construction.
    pub(crate) write_context: WriteContext,
    /// Stable rule fingerprint mapper for the engine used during execution.
    pub(crate) rule_fingerprint: Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>,
    /// Whether the scanner fully traversed the configured start-set
    /// (`Complete`) or stopped early due to resource limits or errors.
    pub(crate) finalize_outcome: FinalizeOutcome,
}

impl GitRepoRuntime {
    /// Execute one Git discovery step for the current shard suffix.
    ///
    /// Delegates to the discovery source's `discover_page` method and wraps
    /// any discovery error into a [`ScanRuntimeError::Driver`] with the
    /// concrete source type name for diagnostics. Returns `None` when no
    /// page is available (the discovery source has no more targets).
    pub(crate) fn execute_discovery<D: GitRepoDiscoverySource>(
        discovery: &mut D,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<PageBuf<GitRepoTarget>>, ScanRuntimeError> {
        discovery
            .discover_page(shard, cursor, budgets)
            .map_err(|error| {
                ScanRuntimeError::Driver(anyhow!(
                    "git-repo discovery failed for source '{}': {error}",
                    std::any::type_name::<D>()
                ))
            })
    }

    /// Execute one already-prepared mirror-backed repository scan.
    ///
    /// Orchestrates two phases:
    ///
    /// 1. **Selection lowering**: explicit-commit selections inside `mirror`
    ///    are resolved to concrete ref names via `lower_selection_for_local_mirror`.
    /// 2. **Executor construction**: a [`ScannerGitExecutor`] is built from the
    ///    overlay of the scan template, payload settings, and lowered selection,
    ///    then paired with a [`GitPersistenceAdapter`] so finalize results land
    ///    durably.
    ///
    /// The returned outcome carries the persistence adapter so the caller can
    /// build the checkpoint input after obtaining durable findings and
    /// done-ledger receipts from the persistence layer.
    ///
    /// # Errors
    ///
    /// - Selection lowering failures (e.g., ref resolution) surface as
    ///   `ScanRuntimeError::Driver`.
    /// - Engine construction or scan execution failures propagate through
    ///   the executor error boundary.
    pub(crate) fn execute_repo<B>(
        scan_template: &GitScanConfig,
        payload: &GitShardPayload,
        mirror: &LocalMirror,
        write_context: WriteContext,
        abort: &AtomicBool,
        event_sink: Arc<dyn GitEventOutput + Send + Sync>,
        backend: B,
    ) -> Result<GitRepoExecutionOutcome<B>, ScanRuntimeError>
    where
        B: GitPersistenceBackend,
    {
        let selection = payload
            .lower_selection_for_local_mirror(mirror, RepoOpenLimits::default())
            .map_err(|error| lower_selection_error(mirror, error))?;
        let runtime_config =
            distributed_git_scan_config(scan_template, mirror, payload, &selection);
        let executor = ScannerGitExecutor::from_runtime_config(&runtime_config, event_sink)?;
        let rule_fingerprint = executor.rule_fingerprint_fn();
        let persistence = GitPersistenceAdapter::new(
            backend,
            payload.repo_id(),
            *write_context.policy_hash().as_bytes(),
        );
        let execution = match executor.run_repo_with_persistence(
            mirror,
            &selection,
            payload.execution_limits(),
            *write_context.policy_hash().as_bytes(),
            abort,
            &persistence,
        ) {
            Ok(exec) => exec,
            Err(error) if abort.load(Ordering::Relaxed) => {
                // Abort was signalled — treat as clean cancellation rather
                // than surfacing an opaque driver error. Log the original
                // error so coincidental non-abort failures remain observable.
                tracing::debug!(
                    repo = %digest_repo_path(mirror.path()),
                    %error,
                    "scan error with abort signalled; treating as cancellation",
                );
                return Ok(GitRepoExecutionOutcome {
                    report: ScanReport::default(),
                    persistence,
                    write_context,
                    rule_fingerprint,
                    finalize_outcome: FinalizeOutcome::Partial { skipped_count: 0 },
                });
            }
            Err(error) => {
                return Err(ScanRuntimeError::Driver(anyhow::Error::new(error).context(
                    format!(
                        "git repo execution failed for '{}'",
                        digest_repo_path(mirror.path())
                    ),
                )));
            }
        };
        let finalize_outcome = execution.result.0.finalize.outcome;
        let report = git_report_to_scan_report(execution.result, execution.scan_elapsed);

        Ok(GitRepoExecutionOutcome {
            report,
            persistence,
            write_context,
            rule_fingerprint,
            finalize_outcome,
        })
    }
}

/// Wrap a [`GitSelectionLoweringError`] into a [`ScanRuntimeError::Driver`]
/// with the mirror's digested path for log-safe diagnostics.
fn lower_selection_error(
    mirror: &LocalMirror,
    error: GitSelectionLoweringError,
) -> ScanRuntimeError {
    ScanRuntimeError::Driver(anyhow!(
        "git selection lowering failed for '{}': {error}",
        digest_repo_path(mirror.path())
    ))
}

/// Build a shard-specific Git scan config by overlaying payload and selection
/// settings onto the worker's scan template.
///
/// The overlay semantics are:
/// - **Template** provides the base rule file, transform filter, decode depth,
///   and anchor mode inherited from the worker identity.
/// - **Mirror path** replaces the template's `repo` field with the prepared
///   mirror location.
/// - **Payload** contributes `repo_id` and execution limits (worker count,
///   binary scanning, identity enrichment, cache/chunk sizes, debug level).
/// - **Selection** supplies scan mode, merge strategy, and ref selection
///   (already lowered from explicit-commit form).
///
/// Fields not overridden by the payload retain the template's default values.
fn distributed_git_scan_config(
    template: &GitScanConfig,
    mirror: &LocalMirror,
    payload: &GitShardPayload,
    selection: &GitSelection,
) -> GitScanConfig {
    let limits = payload.execution_limits();
    let mut config = template.clone();
    config.repo = mirror.path().to_path_buf();
    config.repo_id = payload.repo_id();
    config.scan_mode = map_scan_mode(selection.scan_mode());
    config.merge_mode = map_merge_strategy(selection.merge_strategy());
    config.ref_selection = selection.refs().clone();
    if let Some(workers) = limits.pack_exec_workers() {
        config.workers = workers;
    }
    config.scan_binary = limits.scan_binary();
    config.debug_level = limits.debug_level();
    config.enrich_identities = limits.enrich_identities();
    config.tree_delta_cache_mb = limits.tree_delta_cache_mb();
    config.engine_chunk_mb = limits.engine_chunk_mb();
    config
}

/// Extract the single repo target from a discovery page, enforcing singleton
/// shard invariants.
///
/// Returns `Ok(None)` when `page` is `None` (no discovery result).
/// Returns `Ok(Some(target))` when the page is `Complete` with exactly one
/// item. Returns an error if the page is non-terminal or contains zero or
/// more than one target — both are protocol violations for a singleton shard.
pub(crate) fn single_repo_target(
    page: Option<PageBuf<GitRepoTarget>>,
) -> Result<Option<GitRepoTarget>, ScanRuntimeError> {
    let Some(page) = page else {
        return Ok(None);
    };

    if !matches!(page.state(), PageState::Complete) {
        return Err(ScanRuntimeError::Driver(anyhow!(
            "git repo discovery returned a non-terminal page for a singleton shard"
        )));
    }
    if page.len() != 1 {
        return Err(ScanRuntimeError::Driver(anyhow!(
            "git repo discovery returned {} targets for a singleton shard",
            page.len()
        )));
    }

    Ok(page.items().first().cloned())
}

/// Shared low-level `scanner-git` execution output pairing the scan result
/// with its wall-clock elapsed time.
///
/// Used by both the local and distributed scan paths. The `scan_elapsed`
/// field provides a fallback duration when the scanner's stage-level nanos
/// are unavailable (see [`resolve_scan_ns`]).
pub(crate) struct GitRunExecution {
    /// Raw scan result containing the report, finalize output, and per-stage
    /// timing data.
    pub(crate) result: GitScanResult,
    /// Wall-clock elapsed time measured from scan start to completion, used
    /// as a fallback when stage-level nanos are zero.
    pub(crate) scan_elapsed: Duration,
}

impl GitRunExecution {
    /// Pair a completed scan result with its wall-clock elapsed time.
    pub(crate) fn new(result: GitScanResult, scan_elapsed: Duration) -> Self {
        Self {
            result,
            scan_elapsed,
        }
    }
}

/// Runtime-owned store bundle passed into the shared Git runner helper.
///
/// Callers control incremental behavior by choosing store implementations:
/// - **Local scans** use no-op stores ([`EmptyWatermarkStore`] +
///   [`NeverSeenStore`]) and `persist_store = None` for full scans.
/// - **Distributed scans** inject a [`GitPersistenceAdapter`] that implements
///   all three traits, enabling watermark-driven incremental scanning and
///   durable finalize output.
pub(crate) struct GitRuntimeStores<'a> {
    /// Determines which blobs are considered "already seen" and can be
    /// skipped during the object scan.
    pub(crate) seen_store: &'a dyn SeenBlobStore,
    /// Provides per-ref watermark OIDs so the scanner can skip commits
    /// already covered by a prior scan.
    pub(crate) watermark_store: &'a dyn RefWatermarkStore,
    /// Optional persistence sink for durable finalize output (data ops,
    /// watermark ops). `None` for local scans that do not persist state.
    pub(crate) persist_store: Option<&'a dyn PersistenceStore>,
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
/// a clean EOF rather than blocking indefinitely. Mid-scan cancellation is
/// forwarded into `scanner-git` via `cancel.as_atomic()`, so the scan can stop
/// at cooperative abort checkpoints inside tree walks, blob introduction, and
/// pack-exec scheduling.
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
        let execution = run_runtime_git_scan(
            &canonical_repo,
            engine,
            &git_cfg,
            cancel.as_atomic(),
            git_sink,
        )
        .map_err(|error| {
            ScanRuntimeError::Driver(anyhow!(
                "git scan failed for '{}': {error}",
                digest_repo_path(&canonical_repo)
            ))
        });

        // If cancellation was signalled mid-scan, convert the opaque driver
        // error into a clean early return so callers can distinguish abort
        // from real failures. Log the original error so coincidental
        // non-abort failures remain observable.
        if let Err(ref err) = execution
            && cancel.is_cancelled()
        {
            tracing::debug!(
                repo = %digest_repo_path(&canonical_repo),
                error = %err,
                "scan error with cancellation signalled; treating as cancellation",
            );
            drop(event_tx);
            let _ = join_scoped(event_forwarder, "git event forwarder thread");
            return Ok((ScanReport::default(), None));
        }

        // Close the sender before joining so the forwarder thread sees EOF.
        drop(event_tx);

        // Join the forwarder explicitly before inspecting the scan result.
        // Returning early via `?` would let `std::thread::scope` auto-join
        // the forwarder — and a forwarder panic would mask the scan error.
        let forwarder_result = join_scoped(event_forwarder, "git event forwarder thread")
            .map_err(ScanRuntimeError::Driver);

        // Prefer the scan error (root cause) over the forwarder error.
        let execution = match (execution, forwarder_result) {
            (Err(scan_err), Err(fwd_err)) => {
                tracing::warn!(
                    repo = %digest_repo_path(&canonical_repo),
                    forwarder_error = %fwd_err,
                    "event forwarder also failed after scan error"
                );
                return Err(scan_err);
            }
            (Err(scan_err), Ok(())) => return Err(scan_err),
            (Ok(_), Err(fwd_err)) => return Err(fwd_err),
            (Ok(exec), Ok(())) => exec,
        };

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

/// Apply MiB-denominated size overrides and the binary-scan flag to a
/// pre-built [`RuntimeGitScanConfig`].
///
/// Centralises the overflow-checked MiB-to-bytes conversion for
/// `tree_delta_cache_mb` and `engine_chunk_mb` so callers that build
/// their base config from different sources share a single code path
/// for limit application.
pub(crate) fn apply_scan_limit_overrides(
    cfg: &mut RuntimeGitScanConfig,
    tree_delta_cache_mb: Option<u32>,
    engine_chunk_mb: Option<u32>,
    scan_binary: bool,
) -> Result<(), ScanRuntimeError> {
    cfg.engine_adapter.scan_binary = scan_binary;

    if let Some(value_mb) = tree_delta_cache_mb {
        cfg.tree_diff.max_tree_delta_cache_bytes =
            mebibytes_to_u32_bytes(value_mb, "git_tree_delta_cache_mb")?;
    }
    if let Some(value_mb) = engine_chunk_mb {
        cfg.engine_adapter.chunk_bytes = mebibytes_to_usize_bytes(value_mb, "git_engine_chunk_mb")?;
    }

    Ok(())
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

    apply_scan_limit_overrides(
        &mut git_cfg,
        config.tree_delta_cache_mb,
        config.engine_chunk_mb,
        config.scan_binary,
    )?;

    Ok(git_cfg)
}

/// Execute the shared `scanner-git` runner setup against `canonical_repo`.
///
/// This is the local-runtime convenience wrapper around
/// [`run_runtime_git_scan_with_stores`]. It forwards the caller-owned abort
/// flag unchanged while wiring the non-persistent default stores used by the
/// single-node path.
pub(crate) fn run_runtime_git_scan(
    canonical_repo: &Path,
    engine: Arc<scanner_engine::Engine>,
    git_cfg: &RuntimeGitScanConfig,
    abort: &AtomicBool,
    git_sink: Arc<dyn scanner_git::EventSink>,
) -> Result<GitRunExecution, GitScanError> {
    let watermarks = EmptyWatermarkStore;
    let seen = NeverSeenStore;

    run_runtime_git_scan_with_stores(
        canonical_repo,
        engine,
        git_cfg,
        abort,
        git_sink,
        GitRuntimeStores {
            seen_store: &seen,
            watermark_store: &watermarks,
            persist_store: None,
        },
    )
}

/// Execute the shared `scanner-git` runner setup against `canonical_repo`
/// with caller-provided persistence adapters.
///
/// This helper is the common bridge for both the local runtime path and the
/// distributed mirror-backed executor. It:
///
/// 1. Builds a [`NativeRefResolver`] from the lowered start-set configuration.
/// 2. Forwards the caller-owned cooperative abort flag into `scanner-git`.
/// 3. Wires the selected seen/watermark/persistence stores into the scan.
/// 4. Measures wall-clock elapsed time so higher layers can fall back when the
///    scanner's stage-level timing is unavailable.
///
/// The `abort` flag is borrowed for the duration of the scan and is checked by
/// scanner-git's cooperative cancellation sites. When it is set, the scanner
/// returns `TreeDiffError::Aborted` and skips finalize persistence.
pub(crate) fn run_runtime_git_scan_with_stores(
    canonical_repo: &Path,
    engine: Arc<scanner_engine::Engine>,
    git_cfg: &RuntimeGitScanConfig,
    abort: &AtomicBool,
    git_sink: Arc<dyn scanner_git::EventSink>,
    stores: GitRuntimeStores<'_>,
) -> Result<GitRunExecution, GitScanError> {
    let resolver = NativeRefResolver::new(git_cfg.start_set.clone());
    let scan_start = std::time::Instant::now();
    let result = run_git_scan(
        canonical_repo,
        engine,
        &resolver,
        stores.seen_store,
        stores.watermark_store,
        stores.persist_store,
        git_cfg,
        abort,
        git_sink,
    )?;

    Ok(GitRunExecution::new(result, scan_start.elapsed()))
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
/// Scan duration is resolved by [`resolve_scan_ns`].
///
/// The `scanner_git` report does not track persistence-layer metrics (those
/// flow through a separate `GitPersistenceAdapter` in the distributed path),
/// so `dropped_findings`, `persist_emit_failures`, `persist_incomplete`, and
/// `persist_ns` are zeroed at this translation boundary.
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
    ) -> Result<Vec<Option<RefWatermark>>, RepoOpenError> {
        Ok(vec![None; ref_names.len()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GitScanConfig;
    use gossip_contracts::connector::git::{GitRefSelection, GitRepoTarget, RepoKey, RepoLocator};

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

    fn make_test_target(key_bytes: &[u8]) -> GitRepoTarget {
        GitRepoTarget::new(
            RepoKey::try_from_slice(key_bytes).expect("repo key"),
            RepoLocator::local_path("/tmp/test"),
        )
    }

    #[test]
    fn single_repo_target_none_returns_ok_none() {
        assert!(single_repo_target(None).expect("None input").is_none());
    }

    #[test]
    fn single_repo_target_returns_target_for_single_item_complete_page() {
        let target = make_test_target(b"git:test:repo-a");
        let page = PageBuf::try_new(vec![target.clone()], PageState::Complete).expect("page");

        let result = single_repo_target(Some(page))
            .expect("valid page")
            .expect("should return Some target");
        assert_eq!(result.repo_key(), target.repo_key());
    }

    #[test]
    fn single_repo_target_rejects_non_terminal_page() {
        let target = make_test_target(b"git:test:repo-a");
        let page = PageBuf::try_new(
            vec![target],
            PageState::HasMore {
                cursor: Cursor::initial(),
            },
        )
        .expect("page");

        let err = single_repo_target(Some(page)).expect_err("non-terminal page");
        let msg = format!("{err}");
        assert!(msg.contains("non-terminal page"), "unexpected error: {msg}");
    }

    #[test]
    fn single_repo_target_rejects_multi_item_page() {
        let target_a = make_test_target(b"git:test:repo-a");
        let target_b = make_test_target(b"git:test:repo-b");
        let page = PageBuf::try_new(vec![target_a, target_b], PageState::Complete).expect("page");

        let err = single_repo_target(Some(page)).expect_err("multi-item page");
        let msg = format!("{err}");
        assert!(msg.contains("2 targets"), "unexpected error: {msg}");
    }
}
