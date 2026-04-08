//! Scan execution, per-lease orchestration, and top-level worker loops.
//!
//! Contains the ordered-content page loop, per-shard filesystem and Git
//! execution functions, and the two public entry points: [`run_worker`]
//! (filesystem) and [`run_git_repo_worker`] (repo-frontier).

use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Error as AnyError, Result, anyhow};
use gossip_connectors::FilesystemConnector;
use gossip_contracts::{
    connector::{
        Budgets, Cursor, PageState, ToxicDigest,
        git::{GitMirrorManager, RepoKey},
        ordered::OrderedContentSource,
    },
    coordination::RestoredShardState,
    identity::{LogicalTime, RuleFingerprint, TenantSecretKey},
    persistence::{
        CheckpointBoundary, CheckpointCommitReceipt, CommitScope, DoneLedger,
        DoneLedgerCommitReceipt, FindingsCommitReceipt, FindingsSink, PageCommit, WriteContext,
    },
};
use gossip_coordination::{AcquireScratch, CoordinationFacade, CursorSemantics};
use scanner_git::{FinalizeOutcome, GitEventOutput, PersistenceStore};
use scanner_scheduler::events::EventOutput;

use super::commit_bridge::{
    CommitStageDrainResult, ReceiptCommitSink, checkpoint_logical_time, drain_commit_stage,
    emit_ordered_item_findings, emit_ordered_summary, resolve_filesystem_lease_results,
    wait_for_submitted_commits,
};
use super::lease_ops::{
    ArmedLeaseDeadline, LeaseUncertaintySignal, advance_shard, claim_next_git_lease,
    claim_next_lease, emit_lease_uncertainty, ensure_post_drain_lease_trust, mirror_error_class,
    select_shard_completion, watch_lease_deadline,
};
use super::types::{
    DistributedPersistence, DistributedRunReport, DistributedRuntimeConfig,
    DistributedRuntimeError, GitRunStageMetrics, GitShardLease, GitWorkerIdentity,
    OrderedSourceAssignmentOutcome, PageLoopPhase, PageLoopTermination, ShardCompletionOutcome,
    ShardLease, WorkerIdentity, elapsed_ms, wall_clock_now,
};
use crate::{
    CancellationToken, FsScanConfig, ScanReport, ScanRuntimeError, build_runtime_engine,
    commit_pipeline::{CommitPipeline, CommitPipelineConfig},
    coordination_sink::{
        CoordinationEventRecorder, CoordinationEventSink, FindingsCaptureSink,
        GitFindingForPersistence, StageSignal,
    },
    git_discovery::StaticGitRepoDiscoverySource,
    git_persistence::GitPersistenceBackend,
    git_repo::{GitRepoRuntime, single_repo_target},
    join_scoped,
    ordered_content::{
        OrderedContentExecutionOutcome, OrderedContentRuntime, OrderedContentRuntimeInput,
    },
    result_translation::{ScanTiming, translate_git_item_result},
};

// ---------------------------------------------------------------------------
// Ordered-content scanning (page loop)
// ---------------------------------------------------------------------------

/// Execute ordered-content scanning for one filesystem shard using a
/// [`FilesystemConnector`] as the content source.
///
/// Thin wrapper over [`scan_ordered_source_with_engine`] that constructs a
/// filesystem connector from the shard's hydrated scan config path, then
/// delegates to the generic page loop. Exists as a separate function so the
/// production filesystem path is fully typed while the generic version
/// remains available for test-double injection.
pub(super) fn scan_ordered_filesystem_lease_with_engine<D>(
    lease: &ShardLease,
    config: &FsScanConfig,
    done_ledger: &D,
    engine: Arc<scanner_engine::Engine>,
    out: &dyn EventOutput,
    commit: &ReceiptCommitSink,
    cancel: &CancellationToken,
) -> Result<OrderedSourceAssignmentOutcome, ScanRuntimeError>
where
    D: DoneLedger,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let mut source = FilesystemConnector::new(config.path.clone());
    scan_ordered_source_with_engine(
        &mut source,
        lease,
        config,
        done_ledger,
        engine,
        out,
        commit,
        cancel,
    )
}

/// Source-generic ordered-content page loop.
///
/// Drives a two-phase enumeration and scan cycle:
///
/// 1. **Page enumeration**: requests successive content pages from `source`
///    until the source reports `PageState::Complete` or the loop exits early.
/// 2. **Scan and submit**: each page is pre-filtered against the done-ledger,
///    scanned with the pre-built engine, and committed through
///    `ReceiptCommitSink`. Items past a budget-deferred key or with a
///    retryable outcome stop submission early to preserve checkpoint safety.
///
/// After a terminal non-empty page, the loop enters
/// [`PageLoopPhase::AwaitingExhaustedEmpty`] and expects one confirming
/// `ExhaustedEmpty` response before returning
/// [`PageLoopTermination::ExhaustedEmptyConfirmed`].
///
/// Identical to [`scan_ordered_filesystem_lease_with_engine`] but accepts any
/// [`OrderedContentSource`], enabling injection of scripted test doubles for
/// suffix-protocol verification.
#[allow(clippy::too_many_arguments)]
pub(super) fn scan_ordered_source_with_engine<S, D>(
    source: &mut S,
    lease: &ShardLease,
    config: &FsScanConfig,
    done_ledger: &D,
    engine: Arc<scanner_engine::Engine>,
    out: &dyn EventOutput,
    commit: &ReceiptCommitSink,
    cancel: &CancellationToken,
) -> Result<OrderedSourceAssignmentOutcome, ScanRuntimeError>
where
    S: OrderedContentSource,
    D: DoneLedger,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let budgets = Budgets::try_new(config.budgets.max_items, config.budgets.max_bytes, None)?;
    let shard_spec = lease.restored_state().shard_spec().clone();
    let cursor_semantics = lease.restored_state().cursor_semantics();
    let mut restored_state = lease.restored_state().clone();
    let mut report = ScanReport::default();
    let mut phase = PageLoopPhase::Paging;
    let mut executed_any_page = false;
    let mut termination = PageLoopTermination::Partial;

    loop {
        if cancel.is_cancelled() {
            if phase == PageLoopPhase::AwaitingExhaustedEmpty {
                tracing::debug!(
                    shard_id = %lease.shard_id(),
                    "cancellation during exhausted-empty suffix wait; \
                     partial progress preserved for re-claim",
                );
            }
            break;
        }

        let runtime_input = OrderedContentRuntimeInput::new(restored_state.clone(), budgets);
        let (page, terminal) = match OrderedContentRuntime::execute_source(source, &runtime_input)?
        {
            OrderedContentExecutionOutcome::ExhaustedEmpty => {
                if phase == PageLoopPhase::Paging && executed_any_page {
                    return Err(ScanRuntimeError::Driver(anyhow!(
                        "ordered-content source reported exhausted-empty \
                         without first emitting a terminal non-empty page"
                    )));
                }
                termination = PageLoopTermination::ExhaustedEmptyConfirmed;
                break;
            }
            OrderedContentExecutionOutcome::Stopped(stop) => {
                if phase == PageLoopPhase::AwaitingExhaustedEmpty {
                    if stop.class().is_retryable() {
                        tracing::warn!(
                            message = stop.message(),
                            retry_after_ms = stop.retry_after_ms(),
                            "retryable enumerate stop while waiting for exhausted-empty suffix, preserving receipt-backed progress",
                        );
                        break;
                    }
                    return Err(ScanRuntimeError::Driver(anyhow!(
                        "ordered-content source stopped before confirming \
                         exhausted-empty suffix after a terminal non-empty \
                         page: {stop}"
                    )));
                }
                if stop.class().is_retryable() {
                    if !executed_any_page {
                        // No progress was made — propagate the error so the
                        // shard is not permanently completed as exhausted-empty.
                        // The shard stays active and can be re-claimed.
                        return Err(ScanRuntimeError::Driver(anyhow!(
                            "retryable enumerate failure with no prior progress: {stop}"
                        )));
                    }
                    // Retryable enumerate failure — preserve partial progress
                    // by breaking instead of returning an error. The shard is
                    // completed with a checkpoint at the last committed item,
                    // and the next claim resumes from there.
                    tracing::warn!(
                        message = stop.message(),
                        retry_after_ms = stop.retry_after_ms(),
                        "retryable enumerate stop, preserving partial progress",
                    );
                    break;
                }
                return Err(ScanRuntimeError::Driver(anyhow!("{stop}")));
            }
            OrderedContentExecutionOutcome::Page(page) => {
                if phase == PageLoopPhase::AwaitingExhaustedEmpty {
                    return Err(ScanRuntimeError::Driver(anyhow!(
                        "ordered-content source emitted a non-empty page \
                         after a terminal non-empty page"
                    )));
                }
                let terminal = matches!(page.page().state(), PageState::Complete);
                (page, terminal)
            }
        };

        let page = page.prefilter_done_ledger(lease.write_context(), done_ledger)?;
        let execution = OrderedContentRuntime::execute_scan_misses_with_prebuilt_engine(
            source,
            page,
            config.budgets,
            config.scan_binary,
            Arc::clone(&engine),
        )?;
        executed_any_page = true;

        // Determine the earliest deferred key so we can stop submitting
        // before the checkpoint advances past a budget-deferred item.
        let min_deferred_key = execution
            .deferred()
            .iter()
            .map(|item| item.item_key())
            .min();

        let mut hit_non_terminal = false;
        let mut submitted_report = ScanReport::default();
        let mut items_submitted: u64 = 0;
        for item in execution.outcomes() {
            if cancel.is_cancelled() {
                hit_non_terminal = true;
                break;
            }
            // A deferred item with a key before this outcome means the
            // checkpoint would skip past the deferred item if we commit
            // this outcome. Stop here so the checkpoint stays before the
            // deferred item's key position.
            if let Some(dk) = min_deferred_key
                && dk < item.item().item_key()
            {
                hit_non_terminal = true;
                break;
            }
            // Retryable outcomes (truncated / transient-failure) must not
            // advance the checkpoint — they need to be re-scanned.
            if item.outcome().is_retryable() {
                hit_non_terminal = true;
                break;
            }
            commit
                .submit_ordered_item(item)
                .map_err(ScanRuntimeError::Driver)?;
            emit_ordered_item_findings(out, &engine, item);
            submitted_report += item.report();
            items_submitted += 1;
        }

        // Build the page report from only submitted items so that
        // findings_emitted and other counters reflect what was actually
        // sent to the event stream. Items past the non-terminal break
        // point will be re-scanned on the next claim.
        submitted_report.items_scanned = execution.already_done_len() as u64 + items_submitted;
        submitted_report.items_deferred = execution.deferred().len() as u64;
        report += submitted_report;

        // Non-terminal or deferred items take priority over terminal-page
        // status: if a page was terminal (`PageState::Complete`) but also
        // contained a deferred item, the checkpoint must stop before that
        // item's key. The next claim resumes from the checkpoint and
        // re-discovers the terminal boundary at that time.
        //
        // When neither condition holds, the checkpoint covers all page
        // items committed before the non-terminal boundary. Deferred items
        // may land on a separate page from subsequent outcomes (the page
        // byte budget can split them), so check `deferred()` even when
        // the outcomes loop ran to completion.
        if hit_non_terminal || !execution.deferred().is_empty() {
            break;
        }

        restored_state = RestoredShardState::new(
            shard_spec.clone(),
            execution.resume_cursor().clone(),
            cursor_semantics,
        );
        if terminal {
            phase = PageLoopPhase::AwaitingExhaustedEmpty;
            continue;
        }
    }

    if executed_any_page {
        emit_ordered_summary(out, report);
    }

    Ok(OrderedSourceAssignmentOutcome {
        report,
        termination,
        resume_cursor: restored_state.resume_cursor().clone(),
    })
}

// ---------------------------------------------------------------------------
// Per-lease filesystem execution
// ---------------------------------------------------------------------------

/// Execute one filesystem lease under the receipt-driven durability model.
///
/// This is the per-shard work function called by [`run_worker`]. It
/// orchestrates the full scan-commit-checkpoint pipeline for one shard:
///
/// 1. **Setup**: validates budgets, builds the scan engine, creates the
///    commit pipeline and `ReceiptCommitSink`.
/// 2. **Concurrent execution**: spawns a scoped thread to drain the commit
///    pipeline's outcome stream while the main thread executes bounded
///    ordered-content pages through the filesystem connector runtime until
///    the shard is exhausted.
/// 3. **Post-scan verification**: checks that every submitted sequence
///    number produced exactly one durable outcome (via
///    [`wait_for_submitted_commits`]).
/// 4. **Checkpoint**: prepares and acknowledges the receipt-driven
///    checkpoint prefix through [`crate::checkpoint_aggregator::PrefixCheckpointAggregator`].
///
/// # Design choice: single worker
///
/// The scan runs with `workers = 1` so that `ReceiptCommitSink` sequence
/// assignment remains monotonic without cross-thread synchronization. The
/// commit pipeline provides the parallelism boundary: scan execution and
/// durable commit proceed concurrently on separate threads.
pub(super) fn run_filesystem_lease<F, D>(
    recorder: Arc<dyn CoordinationEventRecorder>,
    persistence: &DistributedPersistence<F, D>,
    lease: &ShardLease,
    config: DistributedRuntimeConfig,
) -> Result<(ScanReport, ShardCompletionOutcome), DistributedRuntimeError>
where
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    config.budgets.validate()?;

    let scan_config = lease
        .scan_config()
        .clone()
        .with_workers(1)
        .with_budgets(config.budgets)
        .with_persist_findings(true);

    if scan_config.workers != 1 {
        return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
            anyhow::anyhow!(
                "receipt-driven execution requires single-threaded scanning, got workers={}",
                scan_config.workers,
            ),
        )));
    }

    let armed_lease_deadline = ArmedLeaseDeadline::arm_from(
        lease.lease().deadline(),
        lease.claim_wall_clock(),
        lease.claim_instant(),
    )
    .map_err(DistributedRuntimeError::LeaseUncertain)?;

    let engine = build_runtime_engine(
        scan_config.rules_file.as_deref(),
        &scan_config.transform_filter,
        scan_config.decode_depth,
        scan_config.anchor_mode,
    )?;
    if let Some(reason) = armed_lease_deadline.expiry_reason() {
        return Err(DistributedRuntimeError::LeaseUncertain(reason));
    }
    let rule_fingerprint = {
        let engine = Arc::clone(&engine);
        Arc::new(move |rule_id| RuleFingerprint::from_bytes(engine.rule_fingerprint_bytes(rule_id)))
            as Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>
    };

    let sink = CoordinationEventSink::new(recorder.clone(), Arc::clone(lease.shard_id_arc()));
    let cancel = CancellationToken::new();
    let lease_uncertainty = LeaseUncertaintySignal::default();
    let lease_watch_done = Arc::new(AtomicBool::new(false));
    let pipeline = CommitPipeline::start(
        persistence.findings_sink.clone(),
        persistence.done_ledger.clone(),
        CommitPipelineConfig {
            execution_queue_capacity: config.commit_queue_capacity.get(),
            outcome_queue_capacity: config.commit_queue_capacity.get(),
        },
        cancel.clone(),
    )
    .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;
    let (submitter, drainer) = pipeline.split();
    let commit = ReceiptCommitSink::new(
        recorder,
        Arc::clone(lease.shard_id_arc()),
        lease.write_context(),
        lease.tenant_secret_key(),
        rule_fingerprint,
        submitter,
    );

    // Scan execution and commit draining run concurrently in a scoped thread.
    // The drain thread consumes commit outcomes and feeds the checkpoint
    // aggregator. When the scan completes, `commit.finish()` consumes the
    // sink (verifying no items remain in-flight) and the drain thread exits
    // once the submission channel closes.
    let (outcome, submitted, stage_result, watch_result) = std::thread::scope(|scope| {
        let write_context = lease.write_context();
        let max_buffered = config.commit_queue_capacity.get();
        let stage_handle = scope.spawn({
            let signal = lease_uncertainty.clone();
            move || {
                let result = drain_commit_stage(drainer, write_context, max_buffered);
                if result.is_ok() {
                    signal.close();
                }
                result
            }
        });
        let deadline_handle = scope.spawn({
            let cancel = cancel.clone();
            let done = Arc::clone(&lease_watch_done);
            let signal = lease_uncertainty.clone();
            move || watch_lease_deadline(armed_lease_deadline, cancel, done, signal)
        });

        let outcome = scan_ordered_filesystem_lease_with_engine(
            lease,
            &scan_config,
            &persistence.done_ledger,
            engine,
            &sink,
            &commit,
            &cancel,
        );
        let submitted = commit.finish();
        let stage_result = join_scoped(stage_handle, "receipt checkpoint drain thread");
        // Keep the watchdog armed until both scan work and receipt-drain
        // resolution finish so expired leases still cancel unfinished shards.
        lease_watch_done.store(true, Ordering::Release);
        deadline_handle.thread().unpark();
        let watch_result = join_scoped(deadline_handle, "lease deadline watchdog");

        (outcome, submitted, stage_result, watch_result)
    });
    watch_result
        .map_err(|error| DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(error)))?;

    let (outcome, submitted, stage_result) = resolve_filesystem_lease_results(
        outcome,
        submitted,
        stage_result,
        lease_uncertainty.current(),
    )?;
    let CommitStageDrainResult {
        mut aggregator,
        committed_sequence_nos,
    } = stage_result;
    let committed_units = committed_sequence_nos.len() as u64;
    let checkpoint_cursor = if committed_units == 0 {
        None
    } else {
        wait_for_submitted_commits(submitted, committed_sequence_nos)
            .map_err(DistributedRuntimeError::Durability)?;

        let (checkpoint_scope, checkpoint_time, checkpoint_cursor) = {
            let pending = aggregator
                .prepare_checkpoint()
                .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;

            let pending = pending.ok_or_else(|| {
                DistributedRuntimeError::Durability(anyhow!(
                    "filesystem shard '{}' committed {} unit(s) but no receipt-driven checkpoint prefix was prepared",
                    lease.shard_id(),
                    committed_units
                ))
            })?;
            if pending.committed_units() != committed_units {
                return Err(DistributedRuntimeError::Durability(anyhow!(
                    "filesystem shard '{}' prepared checkpoint for {} unit(s), expected {}",
                    lease.shard_id(),
                    pending.committed_units(),
                    committed_units
                )));
            }

            (
                pending.scope().clone(),
                checkpoint_logical_time(pending.last_sequence_no())
                    .map_err(DistributedRuntimeError::Durability)?,
                pending.checkpoint_cursor().clone(),
            )
        };
        let checkpoint_receipt = CheckpointCommitReceipt::new(checkpoint_scope, checkpoint_time);
        aggregator
            .acknowledge_checkpoint(checkpoint_receipt)
            .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;

        Some(checkpoint_cursor)
    };

    let OrderedSourceAssignmentOutcome {
        report,
        termination,
        resume_cursor,
    } = outcome;
    let completion = select_shard_completion(
        lease.shard_id(),
        lease.resume_cursor(),
        termination,
        checkpoint_cursor,
        resume_cursor,
    )?;
    ensure_post_drain_lease_trust(&lease_uncertainty)?;

    Ok((report, completion))
}

// ---------------------------------------------------------------------------
// Git repo persistence submission
// ---------------------------------------------------------------------------

/// Bundled metadata for one completed Git repo scan, consumed by the
/// persistence submission helper.
pub(super) struct GitRepoPersistenceInput<'a> {
    pub(super) write_context: WriteContext,
    pub(super) shard_id: &'a ToxicDigest,
    pub(super) repo_key: &'a RepoKey,
    pub(super) repo_id: u64,
    pub(super) bytes_scanned: u64,
    pub(super) findings: &'a [GitFindingForPersistence],
    pub(super) tenant_secret_key: TenantSecretKey,
    pub(super) rule_fingerprint: &'a dyn Fn(u32) -> RuleFingerprint,
    pub(super) claim_time: LogicalTime,
    /// Wall-clock timestamp captured after scan execution *and* persistence
    /// finalize complete. The `(claim_time, complete_time)` interval therefore
    /// measures claim-to-durable-finalize, not claim-to-scan-completion alone.
    pub(super) complete_time: LogicalTime,
}

impl fmt::Debug for GitRepoPersistenceInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitRepoPersistenceInput")
            .field("write_context", &self.write_context)
            .field("shard_id", &self.shard_id)
            .field("repo_key", &self.repo_key)
            .field("repo_id", &self.repo_id)
            .field("bytes_scanned", &self.bytes_scanned)
            .field("findings", &self.findings)
            .field("tenant_secret_key", &self.tenant_secret_key)
            .field("rule_fingerprint", &"<fn>")
            .field("claim_time", &self.claim_time)
            .field("complete_time", &self.complete_time)
            .finish()
    }
}

/// Number of distinct receipt families produced by [`submit_git_repo_persistence`]
/// (findings-commit + done-ledger-commit).
pub(super) const GIT_REPO_RECEIPT_FAMILIES: u64 = 2;

/// Submit the findings and done-ledger records for one completed Git repo scan.
///
/// # Partial write window
///
/// If either persistence submit fails, the shard checkpoint is not advanced and
/// the repo stays reclaimable. On re-claim the repo is re-scanned, so partial
/// durable state remains safe under idempotent upsert semantics.
pub(super) fn submit_git_repo_persistence<F, D>(
    persistence: &DistributedPersistence<F, D>,
    input: &GitRepoPersistenceInput<'_>,
) -> Result<(FindingsCommitReceipt, DoneLedgerCommitReceipt), DistributedRuntimeError>
where
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let timing = ScanTiming::try_new(input.claim_time, input.complete_time).map_err(|error| {
        DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(AnyError::new(error).context(
            format!(
                "git repo-frontier shard '{}' has invalid persistence timing",
                input.shard_id,
            ),
        )))
    })?;
    let translation = translate_git_item_result(
        input.write_context,
        &input.tenant_secret_key,
        input.repo_key,
        input.repo_id,
        input.bytes_scanned,
        timing,
        input.findings,
        input.rule_fingerprint,
    )
    .map_err(|error| {
        DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(AnyError::new(error).context(
            format!(
                "git repo-frontier shard '{}' finding translation failed",
                input.shard_id,
            ),
        )))
    })?;
    // translate_git_item_result -> build_translation validates observation
    // identity, referential integrity, and done-ledger consistency before
    // returning. Repeating those O(N) checks here would double the BLAKE3
    // re-derivation and HashSet work for every finding.
    let findings_batch = translation.findings_batch();

    let scope = CommitScope::from_write_context(
        input.write_context,
        NonZeroU64::MIN,
        CheckpointBoundary::repo_frontier(Cursor::with_last_key(
            input.repo_key.clone().into_item_key(),
        )),
    );
    let page = PageCommit::new(scope);

    // Clean scans (zero findings) skip the findings sink entirely: the
    // only durable row needed is the done-ledger entry. This avoids a
    // round-trip with an empty batch that could fail on some backends and
    // leave the repo reclaimable for no reason.
    let page = if findings_batch.is_empty() {
        page.record_findings(FindingsCommitReceipt::new(0, 0, 0))
    } else {
        let findings_handle = persistence
            .findings_sink
            .upsert_batch(findings_batch)
            .map_err(|error| {
                DistributedRuntimeError::Durability(AnyError::new(error).context(format!(
                    "git repo-frontier shard '{}' findings submission failed",
                    input.shard_id,
                )))
            })?;
        page.wait_findings(findings_handle).map_err(|error| {
            DistributedRuntimeError::Durability(AnyError::new(error).context(format!(
                "git repo-frontier shard '{}' findings durability failed",
                input.shard_id,
            )))
        })?
    };
    let done_handle = persistence
        .done_ledger
        .batch_upsert(std::slice::from_ref(translation.done_ledger()))
        .map_err(|error| {
            DistributedRuntimeError::Durability(AnyError::new(error).context(format!(
                "git repo-frontier shard '{}' done-ledger submission failed",
                input.shard_id,
            )))
        })?;
    let receipt = page.wait_done_ledger(done_handle).map_err(|error| {
        DistributedRuntimeError::Durability(AnyError::new(error).context(format!(
            "git repo-frontier shard '{}' durable persistence commit failed",
            input.shard_id,
        )))
    })?;
    let receipt = receipt.into_item_commit_receipt();

    Ok((receipt.findings(), receipt.done_ledger()))
}

// ---------------------------------------------------------------------------
// Per-lease Git repo-frontier execution
// ---------------------------------------------------------------------------

/// Execute one Git repo-frontier lease under the durable repo-receipt model.
///
/// The current shard contract is a singleton: discovery may yield zero targets
/// (already complete) or exactly one in-scope repo target. A durable complete
/// finalize produces the repo-frontier checkpoint cursor for shard advance.
fn run_git_repo_lease<M, B, F, D>(
    stage_sink: Arc<CoordinationEventSink>,
    identity: &GitWorkerIdentity,
    mirrors: &mut M,
    git_persistence_backend: &B,
    persistence: &DistributedPersistence<F, D>,
    lease: &GitShardLease,
    config: DistributedRuntimeConfig,
) -> Result<(ScanReport, ShardCompletionOutcome, GitRunStageMetrics), DistributedRuntimeError>
where
    M: GitMirrorManager,
    B: GitPersistenceBackend + Clone,
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    config.budgets.validate().map_err(|e| {
        DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(anyhow::Error::from(e).context(
            format!(
                "budget validation failed for git repo-frontier shard '{}'",
                stage_sink.redacted_shard_id()
            ),
        )))
    })?;
    if lease.cursor_semantics() != CursorSemantics::Completed {
        return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
            anyhow!(
                "git repo-frontier shard '{}' requires CursorSemantics::Completed, got {:?}",
                stage_sink.redacted_shard_id(),
                lease.cursor_semantics()
            ),
        )));
    }

    let armed_lease_deadline = ArmedLeaseDeadline::arm_from(
        lease.lease().deadline(),
        lease.claim_wall_clock(),
        lease.claim_instant(),
    )
    .map_err(DistributedRuntimeError::LeaseUncertain)?;
    if let Some(reason) = armed_lease_deadline.expiry_reason() {
        return Err(DistributedRuntimeError::LeaseUncertain(reason));
    }

    let discovery_budgets =
        Budgets::try_new(config.budgets.max_items, config.budgets.max_bytes, None)
            .map_err(ScanRuntimeError::from)
            .map_err(DistributedRuntimeError::Runtime)?;
    let mut discovery = StaticGitRepoDiscoverySource::new(lease.payload().repo_target().clone());
    let page = GitRepoRuntime::execute_discovery(
        &mut discovery,
        lease.shard_spec(),
        lease.resume_cursor(),
        discovery_budgets,
    )
    .map_err(DistributedRuntimeError::Runtime)?;
    let Some(target) = single_repo_target(page).map_err(DistributedRuntimeError::Runtime)? else {
        // Discovery returned no target. Distinguish between a legitimate
        // already-complete cursor (ExhaustedEmpty) and a malformed shard
        // whose payload target falls outside its own key range.
        if !lease
            .shard_spec()
            .contains_key(lease.payload().repo_key().as_bytes())
        {
            return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
                anyhow!(
                    "git repo-frontier shard '{}' payload repo key is outside shard bounds",
                    stage_sink.redacted_shard_id(),
                ),
            )));
        }
        return Ok((
            ScanReport::default(),
            ShardCompletionOutcome::ExhaustedEmpty,
            GitRunStageMetrics::default(),
        ));
    };
    // Defense-in-depth: unreachable with StaticGitRepoDiscoverySource because
    // discovery is built from the payload's repo target, so the discovered key
    // always matches. Guards against future discovery implementations that may
    // resolve a different target than the payload carries.
    if target.repo_key() != lease.payload().repo_key() {
        return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
            anyhow!(
                "git repo-frontier shard '{}' discovered a repo key that does not match the payload",
                stage_sink.redacted_shard_id(),
            ),
        )));
    }

    // The lease-deadline watchdog flips this token when the lease expires.
    // Scanner-git borrows the underlying flag, so mid-scan cancellation
    // can stop tree walks, blob introduction, and pack-exec scheduling before
    // finalize persistence begins. The pre-/post-mirror expiry checks still
    // guard the mirror-sync window around the scan itself.
    let cancel = CancellationToken::new();
    let lease_uncertainty = LeaseUncertaintySignal::default();
    let lease_watch_done = Arc::new(AtomicBool::new(false));
    let capture_sink = Arc::new(FindingsCaptureSink::new(Arc::clone(&stage_sink)));
    let event_sink: Arc<dyn GitEventOutput + Send + Sync> =
        Arc::clone(&capture_sink) as Arc<dyn GitEventOutput + Send + Sync>;
    let (execution, watch_result) = std::thread::scope(|scope| {
        let deadline_handle = scope.spawn({
            let cancel = cancel.clone();
            let done = Arc::clone(&lease_watch_done);
            let signal = lease_uncertainty.clone();
            move || watch_lease_deadline(armed_lease_deadline, cancel, done, signal)
        });

        let execution = (|| -> Result<_, DistributedRuntimeError> {
            let mut stage_metrics = GitRunStageMetrics::default();
            if let Some(reason) = armed_lease_deadline.expiry_reason() {
                return Err(DistributedRuntimeError::LeaseUncertain(reason));
            }

            let mirror_started_at = Instant::now();
            let mirror = mirrors
                .sync_mirror(lease.payload().repo_target().locator())
                .map_err(|error| {
                    stage_sink.emit_stage_signal(StageSignal::MirrorSyncCompleted {
                        latency_ms: elapsed_ms(mirror_started_at),
                        error_class: Some(mirror_error_class(error.class())),
                    });
                    DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
                        anyhow::Error::from(error).context(format!(
                            "git mirror sync failed for shard '{}'",
                            stage_sink.redacted_shard_id(),
                        )),
                    ))
                })?;
            stage_metrics.mirror_sync_ms = elapsed_ms(mirror_started_at);
            stage_sink.emit_stage_signal(StageSignal::MirrorSyncCompleted {
                latency_ms: stage_metrics.mirror_sync_ms,
                error_class: None,
            });

            if let Some(reason) = armed_lease_deadline.expiry_reason() {
                return Err(DistributedRuntimeError::LeaseUncertain(reason));
            }

            let scan_started_at = Instant::now();
            let execution = GitRepoRuntime::execute_repo(
                &identity.scan_template,
                lease.payload(),
                &mirror,
                lease.write_context(),
                cancel.as_atomic(),
                Arc::clone(&event_sink),
                git_persistence_backend.clone(),
            )
            .map_err(|error| {
                stage_sink.emit_stage_signal(StageSignal::ScanCompleted {
                    latency_ms: elapsed_ms(scan_started_at),
                    items_scanned: None,
                    bytes_scanned: None,
                });
                DistributedRuntimeError::Runtime(error)
            })?;
            stage_metrics.scan_ms = elapsed_ms(scan_started_at);
            stage_sink.emit_stage_signal(StageSignal::ScanCompleted {
                latency_ms: stage_metrics.scan_ms,
                items_scanned: Some(execution.report.items_scanned),
                bytes_scanned: Some(execution.report.bytes_scanned),
            });
            Ok((execution, stage_metrics))
        })();

        // Seal the uncertainty signal once the scoped-thread block
        // completes so the watchdog (about to be joined) cannot record a
        // stale note after the block exits.  A separate pre-persistence
        // deadline check below guards the durable write window.
        if execution.is_ok() {
            // Final deadline check while the watchdog is still joinable —
            // narrows the race window where the watchdog parks between the
            // scan completing and waking to observe an elapsed deadline.
            if let Some(reason) = armed_lease_deadline.expiry_reason() {
                lease_uncertainty.note(reason);
            }
            lease_uncertainty.close();
        }

        lease_watch_done.store(true, Ordering::Release);
        deadline_handle.thread().unpark();
        let watch_result = join_scoped(deadline_handle, "lease deadline watchdog");
        (execution, watch_result)
    });
    watch_result
        .map_err(|error| DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(error)))?;

    if let Some(reason) = lease_uncertainty.current() {
        return Err(DistributedRuntimeError::LeaseUncertain(reason));
    }

    let (execution, mut stage_metrics) = execution?;
    let complete_time = wall_clock_now();
    if !matches!(execution.finalize_outcome, FinalizeOutcome::Complete) {
        // Only checkpoint when the scan was externally interrupted (cooperative
        // abort via the cancellation token). A natural Partial finalize (e.g.,
        // corrupt blobs, decode failures) is permanent — retrying from a
        // checkpoint loops indefinitely on the same unrecoverable errors.
        if cancel.is_cancelled() {
            let checkpoint = execution.resume_checkpoint.clone().or_else(|| {
                lease
                    .resume_cursor()
                    .last_key()
                    .map(|_| lease.resume_cursor().clone())
            });
            if let Some(checkpoint) = checkpoint {
                ensure_post_drain_lease_trust(&lease_uncertainty)?;
                return Ok((
                    execution.report,
                    ShardCompletionOutcome::Checkpoint { checkpoint },
                    stage_metrics,
                ));
            }
        }
        return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
            anyhow!(
                "git repo-frontier shard '{}' finalized partially; outer repo-frontier progress requires a complete durable repo receipt",
                stage_sink.redacted_shard_id()
            ),
        )));
    }

    // External findings and done-ledger state must land before a complete Git
    // finalize advances the repo's durable scan state. The scan phase buffers
    // complete finalizes so the git-kv commit can run after these receipts
    // succeed; partial finalizes remain inline because they never advance
    // watermarks.
    let captured_findings = capture_sink.take_captured_findings();
    let detected_count = capture_sink.detected_finding_count();
    if detected_count != captured_findings.len() as u64 {
        return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
            anyhow::anyhow!(
                "git repo-frontier shard '{}': finding counter ({detected_count}) \
                 diverged from captured payload count ({}); \
                 data integrity compromised",
                stage_sink.redacted_shard_id(),
                captured_findings.len(),
            ),
        )));
    }

    let input = GitRepoPersistenceInput {
        write_context: execution.write_context,
        shard_id: stage_sink.redacted_shard_id(),
        repo_key: lease.payload().repo_key(),
        repo_id: lease.payload().repo_id(),
        bytes_scanned: execution.report.bytes_scanned,
        findings: &captured_findings,
        tenant_secret_key: identity.tenant_secret_key,
        rule_fingerprint: &*execution.rule_fingerprint,
        claim_time: lease.claim_wall_clock(),
        complete_time,
    };

    // Guard the durable write window: the watchdog is dead (joined above)
    // so no further uncertainty can be noted. A stale lease detected here
    // avoids wasted persistence work and a guaranteed coordinator rejection
    // on shard advance.
    if let Some(reason) = armed_lease_deadline.expiry_reason() {
        return Err(DistributedRuntimeError::LeaseUncertain(reason));
    }

    let receipt_started_at = Instant::now();
    let (findings_receipt, done_ledger_receipt) = submit_git_repo_persistence(persistence, &input)
        .inspect_err(|_| {
            stage_sink.emit_stage_signal(StageSignal::DurableReceiptCompleted {
                latency_ms: elapsed_ms(receipt_started_at),
                receipts: 0,
            });
        })?;
    stage_metrics.durable_receipt_ms = elapsed_ms(receipt_started_at);
    stage_sink.emit_stage_signal(StageSignal::DurableReceiptCompleted {
        latency_ms: stage_metrics.durable_receipt_ms,
        receipts: GIT_REPO_RECEIPT_FAMILIES,
    });

    // At-least-once guarantee: findings and done-ledger records are already
    // durable at this point. If commit_finalize fails (connection drop,
    // constraint violation) or the process is killed before it completes,
    // watermarks remain at their pre-scan position. The next lease re-scans
    // the same blobs and re-emits findings. Done-ledger and findings
    // consumers must tolerate duplicate submissions.
    if let Some(finalize) = execution.deferred_finalize.as_ref() {
        execution
            .persistence
            .commit_finalize(finalize)
            .map_err(|error| {
                DistributedRuntimeError::Durability(AnyError::new(error).context(format!(
                    "git repo-frontier shard '{}' git state finalize commit failed",
                    stage_sink.redacted_shard_id()
                )))
            })?;
    }

    tracing::debug!(
        shard_id = %stage_sink.redacted_shard_id(),
        detected_findings = detected_count,
        "git repo lease persistence complete"
    );

    // Build the checkpoint input with the real persistence receipts.
    let checkpoint_input = execution
        .persistence
        .repo_frontier_checkpoint_input(
            execution.write_context,
            0,
            lease.payload().repo_key(),
            execution.finalize_outcome,
            findings_receipt,
            done_ledger_receipt,
        )
        .map_err(|error| {
            DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
                anyhow::Error::new(error).context(format!(
                    "git repo durability checkpoint synthesis failed for shard '{}'",
                    stage_sink.redacted_shard_id()
                )),
            ))
        })?;

    debug_assert!(
        checkpoint_input.is_some(),
        "complete finalize must produce a checkpoint input"
    );

    let checkpoint = checkpoint_input
        .as_ref()
        .ok_or_else(|| {
            DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(anyhow!(
                "git repo-frontier shard '{}' completed without a durable repo receipt-backed checkpoint",
                stage_sink.redacted_shard_id()
            )))
        })?
        .receipt()
        .completed_unit()
        .checkpoint_cursor()
        .clone();

    // Post-scan discovery: verify the checkpoint covers the singleton target.
    //
    // Under the current invariant (partial finalize rejected above, so
    // only `FinalizeOutcome::Complete` reaches here), `repo_frontier_receipt`
    // builds `Cursor::with_last_key(repo_key)`, and `cursor_covers_target`
    // evaluates `last_key >= repo_key` — always true. The `Checkpoint`
    // branch is therefore structurally unreachable today but is retained as
    // a defensive guard: if future work introduces partial repo-frontier
    // progress (e.g. incremental within a single repo), the post-discovery
    // check will correctly distinguish Complete from Checkpoint.
    let mut post_discovery =
        StaticGitRepoDiscoverySource::new(lease.payload().repo_target().clone());
    let remaining = GitRepoRuntime::execute_discovery(
        &mut post_discovery,
        lease.shard_spec(),
        &checkpoint,
        discovery_budgets,
    )
    .map_err(DistributedRuntimeError::Runtime)?;
    let completion = if single_repo_target(remaining)
        .map_err(DistributedRuntimeError::Runtime)?
        .is_some()
    {
        tracing::warn!(
            shard_id = %stage_sink.redacted_shard_id(),
            "git repo-frontier singleton shard checkpoint did not cover the target; \
             shard will be re-claimed"
        );
        ShardCompletionOutcome::Checkpoint {
            checkpoint: checkpoint.clone(),
        }
    } else {
        ShardCompletionOutcome::Complete { checkpoint }
    };

    ensure_post_drain_lease_trust(&lease_uncertainty)?;
    Ok((execution.report, completion, stage_metrics))
}

// ---------------------------------------------------------------------------
// Top-level worker loops
// ---------------------------------------------------------------------------

/// Run the distributed worker loop until the coordinator has no more leases.
///
/// This is the top-level entry point for distributed scanning. The loop:
///
/// 1. **Claims** the next available shard from the coordinator, retrying
///    while the run still has active work but every candidate shard is
///    currently leased or the worker is being throttled.
/// 2. **Executes** the shard's filesystem scan through the full
///    scan-commit-checkpoint pipeline.
/// 3. **Advances** the shard lease against the coordinator, either
///    checkpointing partial progress or completing the shard with the
///    receipt-derived cursor.
/// 4. **Repeats** until no shards remain (returns `Ok(report)`) or an error
///    occurs (returns `Err`).
///
/// # Fail-fast semantics
///
/// The loop terminates on the first claim, scan, shard-advance, or
/// lease-uncertainty stop. Uncompleted leases are not explicitly released; the
/// coordination backend reclaims them when their deadlines expire.
///
/// # Errors
///
/// - [`DistributedRuntimeError::Coordinator`] — shard claiming, progress
///   lookup, checkpoint, or completion failed.
/// - [`DistributedRuntimeError::LeaseUncertain`] -- the worker can no longer
///   trust the claimed lease and must stop before terminal completion.
/// - [`DistributedRuntimeError::Runtime`] — scan execution failed.
/// - [`DistributedRuntimeError::Durability`] — the receipt-driven commit
///   pipeline could not confirm durable progress.
pub fn run_worker<C, F, D>(
    coordinator: &mut C,
    identity: WorkerIdentity,
    persistence: DistributedPersistence<F, D>,
    config: DistributedRuntimeConfig,
) -> Result<DistributedRunReport, DistributedRuntimeError>
where
    C: CoordinationFacade,
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let mut scratch = Box::new(AcquireScratch::new());
    let mut report = DistributedRunReport::default();

    loop {
        let lease = match claim_next_lease(coordinator, &identity, &mut scratch) {
            Ok(Some(lease)) => lease,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    leases_seen = report.leases_seen,
                    shards_scanned = report.shards_scanned,
                    "worker loop terminating: shard claim failed",
                );
                return Err(error);
            }
        };
        report.leases_seen = report.leases_seen.saturating_add(1);

        let (scan_report, completion) = match run_filesystem_lease(
            Arc::clone(&identity.recorder),
            &persistence,
            &lease,
            config,
        ) {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    leases_seen = report.leases_seen,
                    shards_scanned = report.shards_scanned,
                    shard_id = %lease.shard_id(),
                    "worker loop terminating: filesystem lease execution failed",
                );
                return Err(error);
            }
        };

        tracing::debug!(
            shard_id = %lease.shard_id(),
            items_scanned = scan_report.items_scanned,
            bytes_scanned = scan_report.bytes_scanned,
            findings_emitted = scan_report.findings_emitted,
            "shard scan complete",
        );

        if let Err(error) = advance_shard(coordinator, identity.tenant, &lease, &completion) {
            tracing::warn!(
                error = %error,
                leases_seen = report.leases_seen,
                shards_scanned = report.shards_scanned,
                shard_id = %lease.shard_id(),
                "worker loop terminating: shard completion failed",
            );
            return Err(error);
        }

        report.shards_scanned = report.shards_scanned.saturating_add(1);
    }

    report.debug_assert_invariant();
    Ok(report)
}

/// Run the distributed Git repo-frontier worker loop until no leases remain.
///
/// Claims singleton repo-frontier shards, mirrors and executes the target
/// repository, then advances the shard from the durable finalize receipt.
/// The outer claim-execute-advance loop structure mirrors [`run_worker`]; both
/// share the generic claim-retry core and shard-advance helper.
pub fn run_git_repo_worker<C, M, B, F, D>(
    coordinator: &mut C,
    mirrors: &mut M,
    identity: GitWorkerIdentity,
    git_persistence_backend: B,
    persistence: DistributedPersistence<F, D>,
    config: DistributedRuntimeConfig,
) -> Result<DistributedRunReport, DistributedRuntimeError>
where
    C: CoordinationFacade,
    M: GitMirrorManager,
    B: GitPersistenceBackend + Clone,
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let mut scratch = Box::new(AcquireScratch::new());
    let mut report = DistributedRunReport::default();

    loop {
        let claim_started_at = Instant::now();
        let lease = match claim_next_git_lease(coordinator, &identity, &mut scratch) {
            Ok(Some(lease)) => lease,
            Ok(None) => break,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    leases_seen = report.leases_seen,
                    shards_scanned = report.shards_scanned,
                    "git repo worker loop terminating: shard claim failed",
                );
                return Err(error);
            }
        };
        report.leases_seen = report.leases_seen.saturating_add(1);
        let claim_ms = elapsed_ms(claim_started_at);
        report.total_claim_ms = report.total_claim_ms.saturating_add(claim_ms);

        let stage_sink = Arc::new(CoordinationEventSink::new(
            Arc::clone(&identity.recorder),
            Arc::clone(lease.shard_id_arc()),
        ));
        stage_sink.emit_stage_signal(StageSignal::ShardClaimed {
            latency_ms: claim_ms,
        });

        let (scan_report, completion, stage_metrics) = match run_git_repo_lease(
            Arc::clone(&stage_sink),
            &identity,
            mirrors,
            &git_persistence_backend,
            &persistence,
            &lease,
            config,
        ) {
            Ok(result) => result,
            Err(error) => {
                if let DistributedRuntimeError::LeaseUncertain(reason) = &error {
                    emit_lease_uncertainty(stage_sink.as_ref(), *reason);
                }
                tracing::warn!(
                    error = %error,
                    leases_seen = report.leases_seen,
                    shards_scanned = report.shards_scanned,
                    shard_id = %stage_sink.redacted_shard_id(),
                    "git repo worker loop terminating: lease execution failed",
                );
                return Err(error);
            }
        };
        stage_metrics.accumulate_into(&mut report);

        tracing::debug!(
            shard_id = %stage_sink.redacted_shard_id(),
            items_scanned = scan_report.items_scanned,
            bytes_scanned = scan_report.bytes_scanned,
            findings_emitted = scan_report.findings_emitted,
            "git repo shard scan complete",
        );

        let checkpoint_started_at = Instant::now();
        if let Err(error) = advance_shard(coordinator, identity.tenant, &lease, &completion) {
            if let DistributedRuntimeError::LeaseUncertain(reason) = &error {
                emit_lease_uncertainty(stage_sink.as_ref(), *reason);
            }
            tracing::warn!(
                error = %error,
                leases_seen = report.leases_seen,
                shards_scanned = report.shards_scanned,
                shard_id = %stage_sink.redacted_shard_id(),
                "git repo worker loop terminating: shard completion failed",
            );
            return Err(error);
        }
        let checkpoint_ms = elapsed_ms(checkpoint_started_at);
        report.total_checkpoint_ms = report.total_checkpoint_ms.saturating_add(checkpoint_ms);
        stage_sink.emit_stage_signal(StageSignal::CheckpointAdvanced {
            latency_ms: checkpoint_ms,
        });

        report.shards_scanned = report.shards_scanned.saturating_add(1);
    }

    report.debug_assert_invariant();
    Ok(report)
}

/// Build a secret-shaped test fixture from non-secret fragments.
///
/// The assembled string matches gitleaks' generic-api-key rule at scan
/// time, but keeping the fragments separate avoids committing a literal
/// that trips secret-detection CI on the source file itself.
#[cfg(any(test, feature = "test-support"))]
pub fn secret_fixture() -> String {
    ["password=", "xK9mP2qL7wN4vR8t"].concat()
}
