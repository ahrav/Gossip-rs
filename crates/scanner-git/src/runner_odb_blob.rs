//! ODB-blob fast-path scan pipeline.
//!
//! Computes the unique blob set from the commit graph and scans it in pack
//! order. If candidate caps or path arena limits are exceeded during blob
//! introduction, retries via the spill/dedupe pipeline.
//!
//! # Pipeline Stages
//!
//! 1. **Blob introduction** -- walks the commit graph and emits
//!    (oid, pack_id, path) candidates for each unique blob. On success the
//!    candidates land directly in the
//!    `PackCandidateCollector`; on overflow (`CandidateLimitExceeded` /
//!    `PathArenaFull`) a fresh introducer is created and the walk is
//!    re-run through a `Spiller` → `MappingBridge` dedupe pipeline.
//!
//! 2. **Pack planning** -- candidates are bucketed by pack id, then a
//!    per-pack plan (topologically sorted decode order including delta base
//!    dependencies) is built on the runner thread.
//!
//! 3. **Pack execution** -- plans are dispatched as scheduler tasks via
//!    `scheduler::Executor`. The strategy selector chooses the scheduler
//!    worker width (`1` for serial, `pack_exec_workers` for parallel).
//!
//! 4. **Loose scan** -- loose object candidates that did not map to any
//!    pack are scanned after all pack plans complete.
//!
//! Outputs are merged in deterministic pack-plan order. In parallel blob
//! introduction mode (`blob_intro_workers > 1`), the selected blob attribution
//! context (`commit_id`, `path`, flags) is race-winner based and may differ
//! across runs or worker counts.

use std::io;
use std::sync::Arc;
use std::time::Instant;

use scanner_engine::Engine;
#[cfg(feature = "git-perf")]
use scanner_scheduler::{alloc_stats, AllocStats};

use super::blob_introducer::{introduce_parallel, BlobIntroStats, BlobIntroducer};
use super::byte_arena::ByteArena;
use super::commit_graph::CommitGraphIndex;
use super::commit_walk::PlannedCommit;
use super::engine_adapter::{CommitMetaContext, EngineAdapter, GitScanCommonMetrics, ScannedBlobs};
use super::errors::TreeDiffError;
use super::mapping_bridge::{MappingBridge, MappingBridgeConfig, MappingStats};
use super::midx::MidxView;
use super::object_store::{ObjectStore, ObjectStoreLayout};
use super::oid_index::OidIndex;
use super::pack_candidates::{
    CappedPackCandidateSink, LooseCandidate, PackCandidate, PackCandidateCollector,
};
use super::pack_io::PackIo;
use super::pack_plan::{bucket_pack_candidates, build_pack_plan_for_pack, PackPlanError};
use super::runner::{
    GitScanAllocStats, GitScanConfig, GitScanError, GitScanStageNanos, ScanModeOutput,
};
use super::seen_store::{SeenBitmapPersister, SeenBlobStore};
use super::spiller::{SpillStats, Spiller};
use super::tree_delta_cache::TreeDeltaCache;
use super::tree_diff::TreeDiffStats;

use super::repo_paths::{
    collect_loose_dirs, collect_pack_dirs, list_pack_files, resolve_pack_paths,
};
use super::runner_exec::{
    append_scanned_blobs, auto_tree_delta_cache_bytes, build_pack_views,
    estimate_path_arena_capacity, execute_pack_plans_with_scheduler, load_midx, make_spill_dir,
    mmap_pack_files, per_worker_cache_bytes, scan_loose_candidates, select_pack_exec_strategy,
    PackExecStrategy, SpillCandidateSink,
};

use super::repo_open::RepoJobState;
use crate::perf_set;

/// Runs the ODB-blob fast-path scan pipeline.
///
/// Walks the commit graph to identify unique blobs, maps them to pack offsets
/// via the MIDX, builds per-pack decode plans, then decodes and scans blob
/// contents through the detection engine. See the module
/// docs for the full stage breakdown and parallelism strategies.
///
/// # Spill / retry
///
/// If the in-memory candidate collector exceeds its capacity or path-arena
/// budget during blob introduction, the fast-path aborts and the function
/// retries the entire introduction through the spill/dedupe pipeline
/// (`Spiller` → `MappingBridge`).  The introducer's seen-set is reset
/// before the retry so every candidate is re-emitted.
///
/// # Determinism
///
/// Pack execution output order is deterministic for a fixed set of candidates.
/// In parallel blob introduction mode, the selected blob context may vary with
/// scheduling. Consumers must not treat `commit_id`/`path` attribution in this
/// mode as deterministic across worker counts.
///
/// # Commit-meta emission
///
/// The [`CommitMetaContext`] bundles the event sink, commit-graph index,
/// identity interner, and emit-once bitset for exactly-once `CommitMeta` event emission per
/// referenced commit across all pack-exec workers and loose-scan adapters
/// spawned by this function. See
/// [`EngineAdapter::stream_findings`](super::engine_adapter::EngineAdapter)
/// for the gating protocol. Event stream ordering is intentionally
/// non-deterministic under parallel workers; findings may appear before
/// matching commit metadata.
///
/// # Parameters
/// - `repo`: opened repository job state (paths, object format, artifacts).
/// - `engine`: detection engine instance for scanning blob contents.
/// - `seen_store`: seen-blob store for deduplication during spill retry.
/// - `seen_persister`: incremental seen-bitmap writer used after each flush.
/// - `cg_index`: commit graph index built from the commit graph.
/// - `plan`: commit plan (planned commits from `introduced_by_plan`).
/// - `config`: scan configuration (limits, worker counts, etc.).
/// - `commit_meta`: event sink + commit-graph index + emit-once bitset.
///
/// # Errors
/// Returns `GitScanError` on MIDX, pack plan, pack exec, or I/O failures.
/// Returns `GitScanError::ConcurrentMaintenance` if artifacts change
/// between planning start and execution start.
#[cfg_attr(not(feature = "git-perf"), allow(unused_variables, unused_mut))]
pub(super) fn run_odb_blob(
    repo: &RepoJobState,
    engine: Arc<Engine>,
    seen_store: &dyn SeenBlobStore,
    seen_persister: &dyn SeenBitmapPersister,
    cg_index: &CommitGraphIndex,
    plan: &[PlannedCommit],
    config: &GitScanConfig,
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

    // Shared spill directory for tree payloads and pack-exec large blobs.
    let spill_dir = match &config.spill_dir {
        Some(path) => path.clone(),
        None => make_spill_dir()?,
    };

    let midx = load_midx(repo)?;
    let mut mapping_cfg = config.mapping;
    let default_mapping_cfg = MappingBridgeConfig::default();
    if mapping_cfg.max_packed_candidates >= default_mapping_cfg.max_packed_candidates {
        // Default-or-higher caps are treated as soft budgets; scale to the
        // repository object count so mapping does not fail on large repos.
        mapping_cfg.max_packed_candidates =
            mapping_cfg.max_packed_candidates.max(midx.object_count());
    }
    mapping_cfg.path_arena_capacity = estimate_path_arena_capacity(
        mapping_cfg.path_arena_capacity,
        mapping_cfg.max_packed_candidates,
        mapping_cfg.max_loose_candidates,
    );
    let object_store_layout = ObjectStoreLayout::from_midx(repo, midx)?;
    let oid_index = OidIndex::from_midx(&midx);
    // Scale tree delta-cache to repo size to reduce base re-inflate churn on
    // large histories while respecting the configured upper bound.
    let auto_cache_bytes = auto_tree_delta_cache_bytes(
        midx.object_count(),
        config.tree_diff.max_tree_delta_cache_bytes,
    );
    // Build mutable caches only when serial intro or serial fallback is used.
    // Parallel-intro success avoids constructing an otherwise unused store.
    let open_object_store = || {
        let tree_delta_cache = TreeDeltaCache::new(auto_cache_bytes);
        ObjectStore::open_with_layout(
            &object_store_layout,
            &config.tree_diff,
            &spill_dir,
            tree_delta_cache,
        )
    };

    // ── Stage 1: blob introduction ───────────────────────────────────
    // When blob_intro_workers > 1, use the parallel path with shared
    // AtomicSeenSets. The parallel path does not support the spill/retry
    // fallback (which is serial-only); on capacity overflow it returns an
    // error that falls through to the serial spill retry below.
    let intro_start = Instant::now();
    // Clamp workers: at least 1, at most the plan length (no empty chunks),
    // and at most 8 because inflate is memory-bandwidth-bound and shows
    // diminishing returns beyond ~8 threads on current hardware.
    let effective_workers = config
        .blob_intro_workers
        .max(1)
        .min(plan.len().max(1))
        .min(8);

    let (intro_stats, mut packed, loose, path_arena, spill_stats, mapping_stats) =
        if effective_workers > 1 {
            // ── Parallel blob introduction ──
            match introduce_parallel(
                effective_workers,
                repo,
                config,
                &spill_dir,
                &object_store_layout,
                cg_index,
                plan,
                &midx,
                &oid_index,
                mapping_cfg.path_arena_capacity,
                mapping_cfg.max_packed_candidates,
                mapping_cfg.max_loose_candidates,
            ) {
                Ok(result) => {
                    perf_set!(
                        stage_nanos,
                        blob_intro,
                        intro_start.elapsed().as_nanos() as u64
                    );
                    let mapping_stats = MappingStats {
                        unique_blobs_in: result.packed.len().saturating_add(result.loose.len())
                            as u64,
                        packed_matched: result.packed.len() as u64,
                        loose_unmatched: result.loose.len() as u64,
                    };
                    (
                        result.stats,
                        result.packed,
                        result.loose,
                        result.path_arena,
                        SpillStats::default(),
                        mapping_stats,
                    )
                }
                Err(
                    TreeDiffError::CandidateLimitExceeded { .. } | TreeDiffError::PathArenaFull,
                ) => {
                    // Parallel path overflowed — fall back to serial spill/retry.
                    let mut object_store = open_object_store()?;
                    run_serial_spill_retry(
                        repo,
                        config,
                        &spill_dir,
                        cg_index,
                        plan,
                        &midx,
                        &oid_index,
                        &mapping_cfg,
                        seen_store,
                        seen_persister,
                        &mut object_store,
                        &mut stage_nanos,
                        intro_start,
                    )?
                }
                Err(err) => return Err(err.into()),
            }
        } else {
            // ── Serial blob introduction (original path) ──
            let mut object_store = open_object_store()?;
            let mut introducer = BlobIntroducer::new(
                &config.tree_diff,
                repo.object_format.oid_len(),
                midx.object_count(),
                mapping_cfg.max_loose_candidates,
                config.engine_adapter.scan_binary,
            );

            let mut collector = PackCandidateCollector::new(
                &midx,
                &oid_index,
                mapping_cfg.path_arena_capacity,
                mapping_cfg.max_packed_candidates,
                mapping_cfg.max_loose_candidates,
            );

            match introducer.introduce(
                &mut object_store,
                cg_index,
                plan,
                &oid_index,
                &mut collector,
            ) {
                Ok(stats) => {
                    perf_set!(
                        stage_nanos,
                        blob_intro,
                        intro_start.elapsed().as_nanos() as u64
                    );
                    let collect_start = Instant::now();
                    let (packed, loose, path_arena) = collector.finish();
                    perf_set!(
                        stage_nanos,
                        pack_collect,
                        collect_start.elapsed().as_nanos() as u64
                    );
                    let mapping_stats = MappingStats {
                        unique_blobs_in: packed.len().saturating_add(loose.len()) as u64,
                        packed_matched: packed.len() as u64,
                        loose_unmatched: loose.len() as u64,
                    };
                    (
                        stats,
                        packed,
                        loose,
                        path_arena,
                        SpillStats::default(),
                        mapping_stats,
                    )
                }
                Err(
                    TreeDiffError::CandidateLimitExceeded { .. } | TreeDiffError::PathArenaFull,
                ) => {
                    // Serial fast path overflowed — retry with spill pipeline.
                    run_serial_spill_retry(
                        repo,
                        config,
                        &spill_dir,
                        cg_index,
                        plan,
                        &midx,
                        &oid_index,
                        &mapping_cfg,
                        seen_store,
                        seen_persister,
                        &mut object_store,
                        &mut stage_nanos,
                        intro_start,
                    )?
                }
                Err(err) => return Err(err.into()),
            }
        };

    // ── Stage 2 + 3: pack planning + execution ──────────────────────
    let pack_plan_start = Instant::now();
    let pack_dirs = collect_pack_dirs(&repo.paths);
    let pack_names = list_pack_files(&pack_dirs)?;
    midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;
    let pack_paths = Arc::new(resolve_pack_paths(&midx, &pack_dirs)?);
    let loose_dirs = Arc::new(collect_loose_dirs(&repo.paths));
    let mut used_pack_ids: Vec<u16> = packed.iter().map(|cand| cand.pack_id).collect();
    used_pack_ids.sort_unstable();
    used_pack_ids.dedup();
    let pack_mmaps = Arc::new(mmap_pack_files(
        pack_paths.as_ref(),
        &used_pack_ids,
        config.pack_mmap,
    )?);
    let pack_views = build_pack_views(pack_mmaps.as_ref(), repo.object_format)?;

    let packed_len = packed.len();
    let loose_len = loose.len();
    let mut pack_plan_stats = Vec::with_capacity(used_pack_ids.len());
    let mut pack_plan_cfg = config.pack_plan;
    let mut pack_plan_delta_deps_total: u64 = 0;
    let mut pack_plan_delta_deps_max: u32 = 0;

    // Guard against concurrent `git gc` / `git repack`: if maintenance
    // ran between the MIDX load and here, pack files may have been
    // repacked or deleted, making the pack views and plans stale.
    if !repo.artifacts_unchanged()? {
        return Err(GitScanError::ConcurrentMaintenance);
    }

    let pack_exec_workers = config.pack_exec_workers.max(1);
    let pack_cache_target = per_worker_cache_bytes(
        config.pack_cache_bytes,
        pack_mmaps.as_ref(),
        &used_pack_ids,
        config.pack_exec_workers,
    );
    let pack_cache_bytes: u32 = pack_cache_target
        .try_into()
        .map_err(|_| io::Error::other("pack cache size exceeds u32::MAX"))?;
    let mut pack_exec_reports = Vec::with_capacity(used_pack_ids.len());
    let mut skipped_candidates = Vec::new();
    let mut common_metrics = GitScanCommonMetrics::default();
    let mut scanned = ScannedBlobs {
        blobs: Vec::with_capacity(packed_len.saturating_add(loose_len)),
        finding_arena: Vec::new(),
    };
    let path_arena = Arc::new(path_arena);
    let spill_dir = Arc::new(spill_dir);

    #[cfg(feature = "git-perf")]
    let mut pack_exec_started = false;
    #[cfg(feature = "git-perf")]
    let mut pack_exec_start = Instant::now();
    #[cfg(feature = "git-perf")]
    let mut pack_exec_alloc_before = AllocStats::default();
    #[cfg(feature = "git-perf")]
    let mut start_pack_exec = || {
        if !pack_exec_started {
            pack_exec_started = true;
            pack_exec_start = Instant::now();
            pack_exec_alloc_before = alloc_stats();
        }
    };

    if packed_len > 0 {
        // Scale worklist/base-lookup caps to 2× candidate count: delta base
        // dependencies can roughly double the entries in the worst case
        // (every candidate is a delta whose base is also enqueued).
        let scaled = packed_len.saturating_mul(2);
        pack_plan_cfg.max_worklist_entries = pack_plan_cfg.max_worklist_entries.max(scaled);
        pack_plan_cfg.max_base_lookups = pack_plan_cfg.max_base_lookups.max(scaled);

        let (mut buckets, pack_ids) = bucket_pack_candidates(packed.drain(..), pack_views.len())?;
        let mut plans = Vec::with_capacity(pack_ids.len());
        for pack_id in pack_ids {
            let pack_idx = pack_id as usize;
            let pack = pack_views
                .get(pack_idx)
                .and_then(|pack| pack.as_ref())
                .ok_or(PackPlanError::PackIdOutOfRange {
                    pack_id,
                    pack_count: pack_views.len(),
                })?;
            let pack_candidates = std::mem::take(&mut buckets[pack_idx]);
            let plan =
                build_pack_plan_for_pack(pack_id, pack, pack_candidates, &midx, &pack_plan_cfg)?;
            pack_plan_stats.push(plan.stats);
            let deps_len = plan.delta_deps.len() as u32;
            pack_plan_delta_deps_total = pack_plan_delta_deps_total.saturating_add(deps_len as u64);
            pack_plan_delta_deps_max = pack_plan_delta_deps_max.max(deps_len);
            plans.push(plan);
        }
        perf_set!(
            stage_nanos,
            pack_plan,
            pack_plan_start.elapsed().as_nanos() as u64
        );

        if !plans.is_empty() {
            #[cfg(feature = "git-perf")]
            start_pack_exec();
            let strategy = select_pack_exec_strategy(pack_exec_workers, &plans);
            let scheduler_workers = match strategy {
                PackExecStrategy::Serial => 1,
                PackExecStrategy::PackParallel | PackExecStrategy::IntraPackSharded { .. } => {
                    pack_exec_workers
                }
            };
            let midx_bytes = repo
                .mmaps
                .midx
                .clone()
                .ok_or_else(|| GitScanError::Io(io::Error::other("midx bytes missing")))?;
            let outputs = execute_pack_plans_with_scheduler(
                Arc::clone(&engine),
                event_sink.clone(),
                midx_bytes,
                repo.object_format,
                Arc::clone(&pack_paths),
                Arc::clone(&loose_dirs),
                Arc::clone(&pack_mmaps),
                Arc::clone(&path_arena),
                Arc::clone(&spill_dir),
                plans,
                config.pack_decode,
                config.pack_io,
                config.engine_adapter,
                pack_cache_bytes,
                scheduler_workers,
                config.pin_threads,
                Arc::clone(&commit_graph_index),
                Arc::clone(&commit_meta_seen),
            )?;
            for output in outputs {
                pack_exec_reports.push(output.report);
                skipped_candidates.extend(output.skipped);
                common_metrics.merge_from(&output.common_metrics);
                append_scanned_blobs(&mut scanned, output.scanned);
            }
        }

        if !loose.is_empty() {
            #[cfg(feature = "git-perf")]
            start_pack_exec();
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
            let loose_start = Instant::now();
            scan_loose_candidates(
                &loose,
                path_arena.as_ref(),
                &mut adapter,
                &mut external,
                &mut skipped_candidates,
            )?;
            perf_set!(
                stage_nanos,
                loose_scan,
                loose_start.elapsed().as_nanos() as u64
            );
            let loose_metrics = adapter.take_metrics();
            common_metrics.merge_from(&loose_metrics);
            append_scanned_blobs(&mut scanned, adapter.take_results());
        }
    } else {
        perf_set!(
            stage_nanos,
            pack_plan,
            pack_plan_start.elapsed().as_nanos() as u64
        );
        if !loose.is_empty() {
            #[cfg(feature = "git-perf")]
            start_pack_exec();
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
            let loose_start = Instant::now();
            scan_loose_candidates(
                &loose,
                path_arena.as_ref(),
                &mut adapter,
                &mut external,
                &mut skipped_candidates,
            )?;
            perf_set!(
                stage_nanos,
                loose_scan,
                loose_start.elapsed().as_nanos() as u64
            );
            let loose_metrics = adapter.take_metrics();
            common_metrics.merge_from(&loose_metrics);
            append_scanned_blobs(&mut scanned, adapter.take_results());
        }
    }

    #[cfg(feature = "git-perf")]
    if pack_exec_started {
        stage_nanos.pack_exec = pack_exec_start.elapsed().as_nanos() as u64;
        let pack_exec_alloc_after = alloc_stats();
        alloc_deltas.pack_exec = pack_exec_alloc_after.since(&pack_exec_alloc_before);
    }

    Ok(ScanModeOutput {
        scanned,
        path_arena: Arc::try_unwrap(path_arena)
            .map_err(|_| GitScanError::Io(io::Error::other("path arena still shared")))?,
        skipped_candidates,
        pack_exec_reports,
        pack_plan_stats,
        pack_plan_config: pack_plan_cfg,
        pack_plan_delta_deps_total,
        pack_plan_delta_deps_max,
        tree_diff_stats: TreeDiffStats::from(intro_stats),
        spill_stats,
        mapping_stats,
        common_metrics,
        stage_nanos,
        alloc_stats: alloc_deltas,
        pack_cache_per_worker_bytes: pack_cache_target,
    })
}

/// Tuple returned by Stage 1 blob introduction (both serial and parallel paths).
///
/// Fields (in order):
/// 0. `BlobIntroStats` -- commit/tree/blob counters from the walk.
/// 1. `Vec<PackCandidate>` -- blobs mapped to MIDX pack offsets.
/// 2. `Vec<LooseCandidate>` -- blobs not in any pack (loose objects).
/// 3. `ByteArena` -- interned file paths referenced by candidates.
/// 4. `SpillStats` -- spill pipeline stats (zeroed when fast path succeeds).
/// 5. `MappingStats` -- mapping bridge stats (synthetic when no bridge used).
type IntroResult = (
    BlobIntroStats,
    Vec<PackCandidate>,
    Vec<LooseCandidate>,
    ByteArena,
    SpillStats,
    MappingStats,
);

/// Runs the serial spill/retry pipeline when the fast path overflows.
///
/// Used by both the parallel and serial blob introduction paths as a
/// fallback when `CandidateLimitExceeded` or `PathArenaFull` is hit.
///
/// # Two-phase approach
///
/// 1. **Re-introduce**: a fresh `BlobIntroducer` re-walks the commit plan,
///    this time emitting candidates into a `Spiller` (disk-backed) instead
///    of the in-memory `PackCandidateCollector`.
/// 2. **Finalize + map**: the spiller is finalized through `seen_store`
///    dedup plus `seen_persister` durability and piped into a
///    `MappingBridge` which maps OIDs to pack offsets and produces the
///    final `PackCandidate` / `LooseCandidate` vectors.
///
/// A fresh introducer is needed because the prior one's seen sets may
/// have accumulated partial state from the failed fast-path attempt.
/// The spiller uses uncapped disk storage, so this path does not overflow.
///
/// # Timing
///
/// `stage_nanos.blob_intro` is set to the sum of the failed first attempt
/// and the successful retry, so callers see the total wall-clock cost.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(feature = "git-perf"), allow(unused_variables, unused_mut))]
fn run_serial_spill_retry(
    repo: &RepoJobState,
    config: &GitScanConfig,
    spill_dir: &std::path::Path,
    cg_index: &CommitGraphIndex,
    plan: &[super::commit_walk::PlannedCommit],
    midx: &MidxView<'_>,
    oid_index: &OidIndex,
    mapping_cfg: &MappingBridgeConfig,
    seen_store: &dyn SeenBlobStore,
    seen_persister: &dyn SeenBitmapPersister,
    object_store: &mut ObjectStore<'_>,
    stage_nanos: &mut GitScanStageNanos,
    intro_start: Instant,
) -> Result<IntroResult, GitScanError> {
    let first_elapsed = intro_start.elapsed().as_nanos() as u64;

    // Build a fresh serial introducer for the retry.
    let mut introducer = BlobIntroducer::new(
        &config.tree_diff,
        repo.object_format.oid_len(),
        midx.object_count(),
        mapping_cfg.max_loose_candidates,
        config.engine_adapter.scan_binary,
    );

    let retry_start = Instant::now();
    let mut spiller = Spiller::new(config.spill, repo.object_format.oid_len(), spill_dir)?;
    let mut sink = SpillCandidateSink::new(&mut spiller);
    let stats = introducer.introduce(object_store, cg_index, plan, oid_index, &mut sink)?;
    let retry_elapsed = retry_start.elapsed().as_nanos() as u64;
    perf_set!(
        stage_nanos,
        blob_intro,
        first_elapsed.saturating_add(retry_elapsed)
    );

    let spill_start = Instant::now();
    let mut bridge = MappingBridge::new(
        midx,
        CappedPackCandidateSink::new(
            mapping_cfg.max_packed_candidates,
            mapping_cfg.max_loose_candidates,
        ),
        *mapping_cfg,
    );
    let spill_stats = spiller.finalize(seen_store, seen_persister, &mut bridge)?;
    perf_set!(stage_nanos, spill, spill_start.elapsed().as_nanos() as u64);
    let (mapping_stats, mut sink, mapping_arena) = bridge.finish()?;
    let packed = std::mem::take(&mut sink.packed);
    let loose = std::mem::take(&mut sink.loose);

    Ok((
        stats,
        packed,
        loose,
        mapping_arena,
        spill_stats,
        mapping_stats,
    ))
}
