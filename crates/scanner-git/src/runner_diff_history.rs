//! Diff-history scan pipeline.
//!
//! Walks commits in topological order, diffs trees to discover changed blobs,
//! spills and deduplicates candidates, then batch-plans and executes pack
//! decode + scan.
//!
//! # Pipeline stages
//!
//! ```text
//! PlannedCommits ──► TreeDiff ──► Spill/Dedupe ──► MappingBridge ──► PackPlan ──► PackExec
//!   (topo order)    (blob OIDs)   (seen filter)    (OID→pack loc)   (per-pack)   (decode+scan)
//! ```
//!
//! 1. **Tree diff** – walks each planned commit, diffs its tree against parent
//!    trees (or the empty tree for snapshot roots) to discover changed blob
//!    OIDs. Candidates stream directly into the spiller to bound memory.
//! 2. **Spill / dedupe** – the spiller externalizes candidates to disk when the
//!    in-memory budget is exceeded, then replays them through the seen-blob
//!    store to drop already-scanned OIDs while durably extending the
//!    seen-bitmap after each flush.
//! 3. **Mapping bridge** – maps surviving OIDs to pack locations via the MIDX,
//!    partitioning into packed and loose candidate sets. Produces a `ByteArena`
//!    of file paths that pack-exec and loose-scan reference by `ByteRef`.
//! 4. **Pack planning** – groups packed candidates by pack file and builds a
//!    topologically-sorted decode plan that respects delta chains.
//! 5. **Pack execution** – decodes pack entries, resolves deltas, and feeds
//!    reconstructed blobs to the detection engine for scanning.
//!
//! # Batch planning
//!
//! All pack plans are built before execution begins, with an artifact
//! staleness check between planning and execution. If `git gc` or
//! `git repack` ran during that window, the function bails with
//! `ConcurrentMaintenance` rather than reading corrupt pack offsets.
//! (The ODB-blob path places this staleness check before planning instead.)
//!
//! # Execution strategies
//!
//! The `PackExecStrategy` enum selects one of three modes based on worker
//! count and plan structure:
//!
//! | Strategy | Condition | Parallelism |
//! |---|---|---|
//! | `Serial` | 1 worker, 0 plans, or tiny total decode work | Scheduler executes pack tasks with 1 worker |
//! | `PackParallel` | enough plans to saturate workers | Scheduler executes pack tasks with `pack_exec_workers` |
//! | `IntraPackSharded` | fewer plans than workers, non-trivial decode work | Scheduler executes pack tasks with `pack_exec_workers` |
//!
//! All three strategies produce **deterministic output order** by reassembling
//! results in planned sequence, regardless of worker completion order.

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[cfg(feature = "git-perf")]
use std::time::Instant;

#[cfg(feature = "git-perf")]
use scanner_scheduler::{alloc_stats, AllocStats};

use crate::{perf_let, perf_set};
use scanner_engine::Engine;

use super::checkpoint::{
    ScanCheckpointError, ScanCheckpointSink, ScanCheckpointStage, ScanResumeState, StageCheckpoint,
};
use super::commit_walk::{CommitGraph, ParentScratch, PlannedCommit};
use super::engine_adapter::{CommitMetaContext, EngineAdapter, GitScanCommonMetrics, ScannedBlobs};
use super::mapping_bridge::{MappingBridge, MappingBridgeConfig, MappingStats};
use super::object_store::{ObjectStore, ObjectStoreLayout};
use super::pack_candidates::CappedPackCandidateSink;
use super::pack_exec::PackExecReport;
use super::pack_io::PackIo;
use super::pack_plan::build_pack_plans;
use super::pack_plan_model::CompletedPacksBitmap;
use super::policy_hash::MergeDiffMode;
use super::repo_open::RepoJobState;
use super::runner::{
    check_abort, checkpoint_stage, GitScanAllocStats, GitScanConfig, GitScanError,
    GitScanStageNanos, ScanModeOutput,
};
use super::seen_store::{SeenBitmapPersister, SeenBlobStore};
use super::spiller::Spiller;
use super::tree_delta_cache::TreeDeltaCache;
use super::tree_diff::TreeDiffWalker;

use super::repo_paths::{
    collect_loose_dirs, collect_pack_dirs, list_pack_files, resolve_pack_paths,
};
use super::runner_exec::{
    append_scanned_blobs, auto_tree_delta_cache_bytes, build_pack_views, collect_scheduler_outputs,
    execute_pack_plans_with_scheduler, load_midx, make_spill_dir, mmap_pack_files,
    per_worker_cache_bytes, plan_completed_cleanly, scan_loose_candidates,
    select_pack_exec_strategy, summarize_pack_plan_deps, PackExecStrategy, SpillCandidateSink,
};

/// Runs the diff-history scan pipeline.
///
/// Walks planned commits, diffs trees to discover changed blobs, streams
/// candidates through the spill/dedupe pipeline, then batch-plans and
/// executes pack decode + scan. See the [module docs](self) for the full
/// pipeline diagram and execution strategy selection.
///
/// The caller (dispatcher) is responsible for finalize, persist, and perf
/// snapshot on the returned output.
///
/// # Determinism
///
/// Output order is deterministic for identical inputs regardless of worker
/// count. Parallel strategies reassemble results by planned sequence index,
/// and loose candidates are always appended after all packed results.
///
/// The returned [`ScanModeOutput`] also carries a completed-pack bitmap sized
/// to `midx.pack_count()`. The runner thread marks a pack only after its final
/// post-scheduler report is assembled, so sharded execution sets the bit after
/// all shards for that pack finish without error-class skips.
///
/// # Lifetime of the returned path arena
///
/// The `path_arena` in the returned [`ScanModeOutput`] owns all file-path
/// bytes referenced by `ByteRef` handles in the scanned blobs and skipped
/// candidates. It must outlive any downstream consumer that dereferences
/// those handles.
///
/// # Commit-meta emission
///
/// The [`CommitMetaContext`] bundles the event sink, commit-graph index,
/// identity interner, and emit-once bitset for exactly-once `CommitMeta` event emission per
/// referenced commit. The index maps commit-graph positions to OIDs and
/// timestamps; the bitset gates emission so each `commit_id` produces at
/// most one `CommitMeta` event even when multiple adapters (or multiple
/// blobs within a single adapter) reference the same commit. Event ordering
/// is intentionally non-deterministic under parallel workers; findings may
/// precede matching commit metadata.
///
/// # Cancellation
///
/// `abort` is checked before each commit diff, at pack-exec and loose-scan
/// stage boundaries, inside the tree-diff walker, and by the scheduler task
/// launcher.
///
/// # Errors
///
/// - MIDX load, completeness, or OID resolution failures.
/// - Pack plan errors (out-of-range pack IDs, corrupt headers).
/// - Pack exec errors (decode failures, delta resolution, I/O).
/// - `GitScanError::ConcurrentMaintenance` if repository artifacts (pack
///   files, indices) changed between pack planning and pack execution,
///   indicating a concurrent `git gc` or `git repack`.
#[cfg_attr(not(feature = "git-perf"), allow(unused_mut))]
pub(super) fn run_diff_history(
    repo: &RepoJobState,
    engine: Arc<Engine>,
    seen_store: &dyn SeenBlobStore,
    seen_persister: &dyn SeenBitmapPersister,
    cg: &dyn CommitGraph,
    plan: &[PlannedCommit],
    config: &GitScanConfig,
    abort: &AtomicBool,
    resume_state: Option<&ScanResumeState>,
    checkpoint_sink: &dyn ScanCheckpointSink,
    commit_meta: CommitMetaContext,
) -> Result<ScanModeOutput, GitScanError> {
    let CommitMetaContext {
        event_sink,
        commit_graph_index,
        commit_meta_seen,
        identity_interner,
    } = commit_meta;

    let mut stage_nanos = GitScanStageNanos::default();
    let mut alloc_deltas = GitScanAllocStats::default();

    // Spill + dedupe (stream candidates during tree diff).
    // Shared spill directory for tree payloads and pack-exec large blobs.
    let spill_dir = match &config.spill_dir {
        Some(path) => path.clone(),
        None => make_spill_dir()?,
    };

    let midx = load_midx(repo)?;
    let mut completed_packs = CompletedPacksBitmap::empty(midx.pack_count() as usize);
    let artifact_fingerprint = repo
        .artifact_fingerprint
        .as_ref()
        .ok_or_else(|| GitScanError::Io(io::Error::other("artifact fingerprint missing")))?;
    let resumed_base = resume_state.and_then(ScanResumeState::base_state);
    let resumed_prefix = resume_state.and_then(ScanResumeState::prefix_state);

    let (tree_diff_stats, spill_stats, mapping_stats, mut packed, loose, mapping_arena) =
        if let Some(base) = resumed_base {
            (
                base.tree_diff_stats.clone(),
                base.spill_stats.clone(),
                base.mapping_stats,
                base.packed.clone(),
                base.loose.clone(),
                base.path_arena.clone(),
            )
        } else {
            let object_store_layout = ObjectStoreLayout::from_midx(repo, midx)?;
            // Scale tree delta-cache to repo size to reduce repeated base decode work
            // while staying within the configured max cache budget.
            let auto_cache_bytes = auto_tree_delta_cache_bytes(
                midx.object_count(),
                config.tree_diff.max_tree_delta_cache_bytes,
            );
            let tree_delta_cache = TreeDeltaCache::new(auto_cache_bytes);
            let mut object_store = ObjectStore::open_with_layout(
                &object_store_layout,
                &config.tree_diff,
                &spill_dir,
                tree_delta_cache,
            )?;
            let mut walker = TreeDiffWalker::new(&config.tree_diff, repo.object_format.oid_len());
            let mut spiller = Spiller::new(config.spill, repo.object_format.oid_len(), &spill_dir)?;
            // Reused across commits to avoid per-commit allocation for parent position lists.
            let mut parent_scratch = ParentScratch::new();

            // ── Stage 1: Tree diff ──────────────────────────────────────────
            {
                perf_let!(diff_start = Instant::now());
                let mut sink = SpillCandidateSink::new(&mut spiller);
                for PlannedCommit { pos, snapshot_root } in plan {
                    check_abort(abort)?;
                    let commit_id = pos.0;
                    let new_tree = cg.root_tree_oid(*pos)?;

                    if *snapshot_root {
                        walker.diff_trees(
                            &mut object_store,
                            &mut sink,
                            Some(&new_tree),
                            None,
                            commit_id,
                            0,
                            abort,
                        )?;
                        continue;
                    }

                    parent_scratch.clear();
                    cg.collect_parents(
                        *pos,
                        config.commit_walk.max_parents_per_commit,
                        &mut parent_scratch,
                    )?;
                    let parents = parent_scratch.as_slice();

                    if parents.is_empty() {
                        walker.diff_trees(
                            &mut object_store,
                            &mut sink,
                            Some(&new_tree),
                            None,
                            commit_id,
                            0,
                            abort,
                        )?;
                        continue;
                    }

                    match config.merge_diff_mode {
                        MergeDiffMode::AllParents => {
                            for (idx, parent_pos) in parents.iter().enumerate() {
                                let old_tree = cg.root_tree_oid(*parent_pos)?;
                                walker.diff_trees(
                                    &mut object_store,
                                    &mut sink,
                                    Some(&new_tree),
                                    Some(&old_tree),
                                    commit_id,
                                    idx as u8,
                                    abort,
                                )?;
                            }
                        }
                        MergeDiffMode::FirstParentOnly => {
                            let old_tree = cg.root_tree_oid(parents[0])?;
                            walker.diff_trees(
                                &mut object_store,
                                &mut sink,
                                Some(&new_tree),
                                Some(&old_tree),
                                commit_id,
                                0,
                                abort,
                            )?;
                        }
                    }
                }
                perf_set!(
                    stage_nanos,
                    tree_diff,
                    diff_start.elapsed().as_nanos() as u64
                );
            }

            // ── Stages 2–3: Spill/dedupe → mapping bridge ──────────────────
            perf_let!(spill_start = Instant::now());
            let mut mapping_cfg = config.mapping;
            let default_mapping_cfg = MappingBridgeConfig::default();
            if mapping_cfg.max_packed_candidates >= default_mapping_cfg.max_packed_candidates {
                mapping_cfg.max_packed_candidates =
                    mapping_cfg.max_packed_candidates.max(midx.object_count());
            }
            let mut bridge = MappingBridge::new(
                &midx,
                CappedPackCandidateSink::new(
                    mapping_cfg.max_packed_candidates,
                    mapping_cfg.max_loose_candidates,
                ),
                mapping_cfg,
            );
            check_abort(abort)?;
            let spill_stats = spiller.finalize(seen_store, seen_persister, &mut bridge)?;
            perf_set!(stage_nanos, spill, spill_start.elapsed().as_nanos() as u64);
            let (mapping_stats, mut sink, mapping_arena) = bridge.finish()?;
            let tree_diff_stats = walker.stats().clone();

            checkpoint_stage(
                checkpoint_sink,
                &StageCheckpoint::PostSpillDedup {
                    scan_mode: config.scan_mode,
                    artifact_fingerprint,
                    plan,
                    packed: &sink.packed,
                    loose: &sink.loose,
                    path_arena: &mapping_arena,
                    tree_diff_stats: tree_diff_stats.clone(),
                    spill_stats: spill_stats.clone(),
                    mapping_stats,
                },
            )?;

            (
                tree_diff_stats,
                spill_stats,
                mapping_stats,
                std::mem::take(&mut sink.packed),
                std::mem::take(&mut sink.loose),
                mapping_arena,
            )
        };
    check_abort(abort)?;

    // ── Stage 4: Pack planning ───────────────────────────────────────────
    perf_let!(pack_plan_start = Instant::now());
    let checkpoint_packed = packed.clone();
    let checkpoint_loose = loose.clone();
    packed.retain(|cand| !completed_packs.is_complete(cand.pack_id));
    let pack_dirs = collect_pack_dirs(&repo.paths);
    let pack_names = list_pack_files(&pack_dirs)?;
    midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;
    let pack_paths = resolve_pack_paths(&midx, &pack_dirs)?;
    // Only mmap packs that contain at least one candidate. This avoids
    // wasting address space on multi-pack repos where most packs are idle.
    let mut used_pack_ids: Vec<u16> = packed.iter().map(|cand| cand.pack_id).collect();
    used_pack_ids.sort_unstable();
    used_pack_ids.dedup();
    let pack_mmaps = mmap_pack_files(&pack_paths, &used_pack_ids, config.pack_mmap)?;
    let pack_views = build_pack_views(&pack_mmaps, repo.object_format)?;

    let mut pack_plan_stats = Vec::new();
    let mut plans = Vec::new();
    let packed_len = packed.len();
    let loose_len = loose.len();
    if !packed.is_empty() {
        let mut pack_plans = build_pack_plans(packed, &pack_views, &midx, &config.pack_plan)?;
        pack_plan_stats.extend(pack_plans.iter().map(|p| p.stats));
        plans.append(&mut pack_plans);
    }
    let (pack_plan_delta_deps_total, pack_plan_delta_deps_max) = summarize_pack_plan_deps(&plans);
    perf_set!(
        stage_nanos,
        pack_plan,
        pack_plan_start.elapsed().as_nanos() as u64
    );
    check_abort(abort)?;

    // Gate between planning and execution: if pack files or indices were
    // rewritten by a concurrent `git gc` / `git repack`, the offsets in our
    // plans are stale. Bail early rather than reading garbage.
    if !repo.artifacts_unchanged()? {
        return Err(GitScanError::ConcurrentMaintenance);
    }

    // ── Stage 5: Pack execution + loose scan ──────────────────────────────
    // Packed candidates are dispatched via the scheduler (serial, pack-
    // parallel, or intra-pack-sharded). Loose candidates are decoded and
    // scanned sequentially after all pack work completes. Both paths feed
    // the same `scanned` accumulator for deterministic output order.
    let pack_cache_target = per_worker_cache_bytes(
        config.pack_cache_bytes,
        &pack_mmaps,
        &used_pack_ids,
        config.pack_exec_workers,
    );
    let pack_cache_bytes: u32 = pack_cache_target
        .try_into()
        .map_err(|_| io::Error::other("pack cache size exceeds u32::MAX"))?;
    let pack_exec_workers = config.pack_exec_workers.max(1);
    let plan_count = plans.len();
    let prefix_resume = resumed_prefix.filter(|prefix| {
        matches!(
            prefix.stage,
            ScanCheckpointStage::PackPlanComplete | ScanCheckpointStage::PreFinalize
        )
    });
    let checkpointing_enabled = checkpoint_sink.checkpoints_enabled() || prefix_resume.is_some();
    let mut completed_plan_prefix_len = prefix_resume
        .map(|prefix| prefix.completed_plan_count)
        .unwrap_or(0);
    let loose_dirs = Arc::new(collect_loose_dirs(&repo.paths));
    let pack_paths = Arc::new(pack_paths);
    let pack_mmaps = Arc::new(pack_mmaps);
    let mapping_arena = Arc::new(mapping_arena);
    let spill_dir = Arc::new(spill_dir);
    let mut pack_exec_reports = Vec::with_capacity(plan_count);
    let mut skipped_candidates = prefix_resume
        .map(|prefix| prefix.skipped_candidates.clone())
        .unwrap_or_default();
    let mut common_metrics = prefix_resume
        .map(|prefix| prefix.common_metrics)
        .unwrap_or_default();
    let mut scanned = prefix_resume
        .map(|prefix| prefix.scanned.clone())
        .unwrap_or_else(|| ScannedBlobs {
            blobs: Vec::with_capacity(packed_len.saturating_add(loose_len)),
            finding_arena: Vec::new(),
        });

    #[cfg(feature = "git-perf")]
    let pack_exec_start = Instant::now();
    #[cfg(feature = "git-perf")]
    let pack_exec_alloc_before: AllocStats = alloc_stats();
    if completed_plan_prefix_len > plans.len() {
        return Err(ScanCheckpointError::InvalidState(format!(
            "resume checkpoint completed {completed_plan_prefix_len} pack plans but rebuilt only {}",
            plans.len()
        ))
        .into());
    }
    if !plans.is_empty() {
        check_abort(abort)?;
        let plan_pack_ids: Vec<u16> = plans.iter().map(|plan| plan.pack_id()).collect();
        for pack_id in plan_pack_ids
            .iter()
            .take(completed_plan_prefix_len)
            .copied()
        {
            completed_packs.mark_complete(pack_id);
        }
        pack_exec_reports.resize_with(completed_plan_prefix_len, PackExecReport::default);
        let midx_bytes = repo
            .mmaps
            .midx
            .clone()
            .ok_or_else(|| GitScanError::Io(io::Error::other("midx bytes missing")))?;

        if matches!(
            resume_state.map(ScanResumeState::stage),
            Some(ScanCheckpointStage::PreFinalize)
        ) {
            pack_exec_reports.resize_with(plans.len(), PackExecReport::default);
        } else if checkpointing_enabled {
            for (plan_idx, pack_plan) in plans
                .into_iter()
                .enumerate()
                .skip(completed_plan_prefix_len)
            {
                let strategy =
                    select_pack_exec_strategy(pack_exec_workers, std::slice::from_ref(&pack_plan));
                let scheduler_workers = match strategy {
                    PackExecStrategy::Serial => 1,
                    PackExecStrategy::PackParallel | PackExecStrategy::IntraPackSharded { .. } => {
                        pack_exec_workers
                    }
                };
                let outputs = execute_pack_plans_with_scheduler(
                    Arc::clone(&engine),
                    event_sink.clone(),
                    midx_bytes.clone(),
                    repo.object_format,
                    Arc::clone(&pack_paths),
                    Arc::clone(&loose_dirs),
                    Arc::clone(&pack_mmaps),
                    Arc::clone(&mapping_arena),
                    Arc::clone(&spill_dir),
                    vec![pack_plan],
                    config.pack_decode,
                    config.pack_io,
                    config.engine_adapter,
                    pack_cache_bytes,
                    scheduler_workers,
                    config.pin_threads,
                    abort,
                    Arc::clone(&commit_graph_index),
                    Arc::clone(&commit_meta_seen),
                )?;
                collect_scheduler_outputs(
                    &plan_pack_ids[plan_idx..=plan_idx],
                    outputs,
                    &mut completed_packs,
                    &mut pack_exec_reports,
                    &mut skipped_candidates,
                    &mut common_metrics,
                    &mut scanned,
                )?;
                if pack_exec_reports.last().is_some_and(plan_completed_cleanly)
                    && plan_idx == completed_plan_prefix_len
                {
                    completed_plan_prefix_len += 1;
                    checkpoint_stage(
                        checkpoint_sink,
                        &StageCheckpoint::PackPlanComplete {
                            scan_mode: config.scan_mode,
                            artifact_fingerprint,
                            plan,
                            packed: &checkpoint_packed,
                            loose: &checkpoint_loose,
                            path_arena: mapping_arena.as_ref(),
                            tree_diff_stats: tree_diff_stats.clone(),
                            spill_stats: spill_stats.clone(),
                            mapping_stats,
                            completed_plan_count: completed_plan_prefix_len,
                            scanned: &scanned,
                            skipped_candidates: &skipped_candidates,
                            common_metrics,
                        },
                    )?;
                }
            }
        } else {
            let strategy = select_pack_exec_strategy(pack_exec_workers, &plans);
            let scheduler_workers = match strategy {
                PackExecStrategy::Serial => 1,
                PackExecStrategy::PackParallel | PackExecStrategy::IntraPackSharded { .. } => {
                    pack_exec_workers
                }
            };
            let outputs = execute_pack_plans_with_scheduler(
                Arc::clone(&engine),
                event_sink.clone(),
                midx_bytes,
                repo.object_format,
                Arc::clone(&pack_paths),
                Arc::clone(&loose_dirs),
                Arc::clone(&pack_mmaps),
                Arc::clone(&mapping_arena),
                Arc::clone(&spill_dir),
                plans,
                config.pack_decode,
                config.pack_io,
                config.engine_adapter,
                pack_cache_bytes,
                scheduler_workers,
                config.pin_threads,
                abort,
                Arc::clone(&commit_graph_index),
                Arc::clone(&commit_meta_seen),
            )?;
            collect_scheduler_outputs(
                &plan_pack_ids,
                outputs,
                &mut completed_packs,
                &mut pack_exec_reports,
                &mut skipped_candidates,
                &mut common_metrics,
                &mut scanned,
            )?;
            completed_plan_prefix_len = pack_exec_reports
                .iter()
                .take_while(|report| plan_completed_cleanly(report))
                .count();
        }
    }
    if !loose.is_empty()
        && !matches!(
            resume_state.map(ScanResumeState::stage),
            Some(ScanCheckpointStage::PreFinalize)
        )
    {
        check_abort(abort)?;
        let mut adapter = EngineAdapter::new_with_event_sink(
            engine.as_ref(),
            config.engine_adapter,
            CommitMetaContext {
                event_sink: event_sink.clone(),
                commit_graph_index: Arc::clone(&commit_graph_index),
                commit_meta_seen: Arc::clone(&commit_meta_seen),
                identity_interner: identity_interner.clone(),
            },
        );
        adapter.reserve_results(loose.len());
        let mut external = PackIo::from_parts(
            midx,
            (*pack_paths).clone(),
            (*loose_dirs).clone(),
            config.pack_io,
        )
        .map_err(GitScanError::PackIo)?;
        scan_loose_candidates(
            &loose,
            mapping_arena.as_ref(),
            &mut adapter,
            &mut external,
            abort,
            &mut skipped_candidates,
        )?;
        let loose_metrics = adapter.take_metrics();
        common_metrics.merge_from(&loose_metrics);
        append_scanned_blobs(&mut scanned, adapter.take_results());
    }
    perf_set!(
        stage_nanos,
        pack_exec,
        pack_exec_start.elapsed().as_nanos() as u64
    );
    #[cfg(feature = "git-perf")]
    {
        let pack_exec_alloc_after = alloc_stats();
        alloc_deltas.pack_exec = pack_exec_alloc_after.since(&pack_exec_alloc_before);
    }

    if !matches!(
        resume_state.map(ScanResumeState::stage),
        Some(ScanCheckpointStage::PreFinalize)
    ) {
        checkpoint_stage(
            checkpoint_sink,
            &StageCheckpoint::PreFinalize {
                scan_mode: config.scan_mode,
                artifact_fingerprint,
                plan,
                packed: &checkpoint_packed,
                loose: &checkpoint_loose,
                path_arena: mapping_arena.as_ref(),
                tree_diff_stats: tree_diff_stats.clone(),
                spill_stats: spill_stats.clone(),
                mapping_stats,
                completed_plan_count: completed_plan_prefix_len,
                scanned: &scanned,
                skipped_candidates: &skipped_candidates,
                common_metrics,
            },
        )?;
    }

    Ok(ScanModeOutput {
        scanned,
        path_arena: Arc::try_unwrap(mapping_arena)
            .map_err(|_| GitScanError::Io(io::Error::other("path arena still shared")))?,
        skipped_candidates,
        pack_exec_reports,
        completed_packs,
        pack_plan_stats,
        pack_plan_config: config.pack_plan,
        pack_plan_delta_deps_total,
        pack_plan_delta_deps_max,
        tree_diff_stats,
        spill_stats,
        mapping_stats,
        common_metrics,
        stage_nanos,
        alloc_stats: alloc_deltas,
        pack_cache_per_worker_bytes: pack_cache_target,
    })
}
