//! Shared pack execution helpers for the Git scan runner.
//!
//! Contains standalone building-block functions used by both scan mode
//! pipelines ([`runner_odb_blob`](super::runner_odb_blob) and
//! [`runner_diff_history`](super::runner_diff_history)). Each mode file
//! owns its execution loop; this module provides the pieces they call:
//!
//! - **Spill directory setup** — unique temp directory for candidate spilling.
//! - **Mmap management** — map pack files, apply sequential access hints.
//! - **Pack view parsing** — validate headers, build `PackView`s for planning.
//! - **Pack cache sizing** — layered heuristic (`estimate_pack_cache_bytes` →
//!   [`per_worker_cache_bytes`]) that balances hit-rate against aggregate memory.
//! - **Loose scanning** — decode loose objects and feed them to the engine.
//! - **Threading utilities** — stats-free strategy selection, index sharding, result merging.
//! - **Spill adapter** — [`SpillCandidateSink`] bridges [`CandidateSink`] to [`Spiller`].
//!
//! # Design note
//!
//! Functions here are intentionally stateless: they accept explicit inputs and
//! return values rather than mutating shared runner state. This keeps the
//! mode-specific pipelines testable in isolation and makes threading boundaries
//! explicit (e.g. `merge_scanned_blobs` expects shards produced by independent
//! workers).

use std::fs;
use std::fs::File;
use std::io;
use std::mem::ManuallyDrop;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use memmap2::Mmap;

use super::byte_arena::ByteArena;
use super::bytes::BytesView;
use super::engine_adapter::{
    CommitMetaContext, EngineAdapter, EngineAdapterConfig, GitScanCommonMetrics, ScannedBlobs,
};
use super::errors::TreeDiffError;
use super::finalize::RefEntry;
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::ObjectFormat;
use super::pack_cache::PackCache;
use super::pack_candidates::LooseCandidate;
use super::pack_decode::PackDecodeLimits;
use super::pack_exec::{
    build_candidate_ranges, execute_pack_plan_with_scratch,
    execute_pack_plan_with_scratch_indices_hot_deps, execute_pack_plan_with_scratch_range_hot_deps,
    merge_pack_exec_reports, CandidateRange, PackExecError, PackExecReport, PackExecScratch,
    PackPlanHotDeps, SkipRecord,
};
use super::pack_inflate::ObjectKind;
use super::pack_io::{PackIo, PackIoError, PackIoLimits};
use super::pack_plan::{PackPlanError, PackView};
use super::pack_plan_model::{BaseLoc, PackPlan, NONE_U32};
use super::repo_open::RepoJobState;
use super::runner::{CandidateSkipReason, GitScanError, PackMmapLimits, SkippedCandidate};
use super::spiller::Spiller;
use super::tree_candidate::CandidateSink;
use crate::events::EventSink;
use scanner_engine::Engine;
use scanner_scheduler::{Executor, ExecutorConfig, WorkerCtx};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Pack cache sizing forms a layered hierarchy applied by `per_worker_cache_bytes`:
//
//   raw estimate  = total_pack_bytes / PACK_CACHE_FRACTION_DENOM  (~6.25 %)
//   per-worker cap = PACK_CACHE_TOTAL_MAX_BYTES / workers         (aggregate bound)
//   per-worker min = PACK_CACHE_PER_WORKER_MIN                    (functional floor)
//   hard ceiling   = PACK_CACHE_MAX_BYTES                         (per-worker cap)
//
// The min-floor can exceed the per-worker cap, which is intentional: a
// worker with too little cache is worse than slightly exceeding the
// aggregate target.

/// Heuristic bytes-per-candidate for path arena sizing.
///
/// Average git path length is ~40 bytes; 64 adds headroom for longer paths
/// without over-allocating for small repos. The estimate is multiplied by
/// candidate count and clamped to `u32::MAX` in [`estimate_path_arena_capacity`].
pub(super) const PATH_BYTES_PER_CANDIDATE_ESTIMATE: u64 = 64;

/// Denominator for the pack cache sizing fraction.
///
/// The pack cache receives `total_mapped_bytes / 16` (~6.25 % of pack data).
/// This fraction provides sufficient working-set coverage for large repos
/// while remaining bounded by [`PACK_CACHE_TOTAL_MAX_BYTES`] so aggregate memory stays
/// controlled.
pub(super) const PACK_CACHE_FRACTION_DENOM: u64 = 16;

/// Hard upper bound per worker for the pack cache (2 GiB).
///
/// Prevents runaway allocation on repos with many large packs.
pub(super) const PACK_CACHE_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Aggregate memory cap across all workers (16 GiB).
///
/// With N workers each sizing caches independently, the per-worker estimate
/// could sum to excessive totals (e.g. 24 × 800 MiB = 19.2 GiB on a ~13 GiB
/// repo). This cap divides evenly across workers so total cache memory stays
/// bounded regardless of pack size or worker count. With 20 workers each
/// gets up to 819 MiB — enough for large repos without starving small ones.
pub(super) const PACK_CACHE_TOTAL_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Minimum per-worker cache budget (32 MiB).
///
/// Ensures each worker has a functional cache even when the total cap is
/// divided among many workers. Below this threshold, cache sets are too few
/// to maintain reasonable hit rates.
pub(super) const PACK_CACHE_PER_WORKER_MIN: u64 = 32 * 1024 * 1024;

// ---------------------------------------------------------------------------
// SpillCandidateSink
// ---------------------------------------------------------------------------

/// Candidate sink that forwards tree-diff output to the spill/dedupe stage.
///
/// Bridges [`CandidateSink`] (the trait consumed by tree-diff walkers) to
/// [`Spiller::push`], translating spill I/O errors into [`TreeDiffError`].
/// This lets the diff-history pipeline emit candidates directly into the
/// spiller without an intermediate buffer.
pub(super) struct SpillCandidateSink<'a> {
    spiller: &'a mut Spiller,
}

impl<'a> SpillCandidateSink<'a> {
    pub(super) fn new(spiller: &'a mut Spiller) -> Self {
        Self { spiller }
    }
}

impl CandidateSink for SpillCandidateSink<'_> {
    fn emit(
        &mut self,
        oid: super::object_id::OidBytes,
        path: &[u8],
        commit_id: u32,
        parent_idx: u8,
        change_kind: super::tree_candidate::ChangeKind,
        ctx_flags: u16,
        cand_flags: u16,
    ) -> Result<(), TreeDiffError> {
        self.spiller
            .push(
                oid,
                path,
                commit_id,
                parent_idx,
                change_kind,
                ctx_flags,
                cand_flags,
            )
            .map_err(|err| TreeDiffError::CandidateSinkError {
                detail: err.to_string(),
            })
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Create a unique spill directory under the OS temp directory.
///
/// The directory name is derived from the PID and a nanosecond timestamp
/// to avoid collisions between concurrent scans. The caller owns the
/// directory and is responsible for cleanup (typically via [`Spiller`] drop).
pub(super) fn make_spill_dir() -> Result<PathBuf, io::Error> {
    // unwrap: SystemTime::now() is always ≥ UNIX_EPOCH on any supported platform.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "git_scan_spill_{}_{}",
        std::process::id(),
        now.as_nanos()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Estimate a path arena capacity based on candidate volume.
///
/// Returns `max(base, (packed + loose) * PATH_BYTES_PER_CANDIDATE_ESTIMATE)`,
/// clamped to `u32::MAX`. The heuristic avoids arena overflow when candidate
/// counts greatly exceed the default `base` capacity.
pub(super) fn estimate_path_arena_capacity(base: u32, packed: u32, loose: u32) -> u32 {
    let total = packed as u64 + loose as u64;
    let est = total
        .saturating_mul(PATH_BYTES_PER_CANDIDATE_ESTIMATE)
        .min(u32::MAX as u64) as u32;
    base.max(est)
}

/// Auto-sizes the tree delta cache based on MIDX object count.
///
/// Heuristic: ~15% of objects are trees in typical repos. Each tree delta
/// base needs ~4 KiB (one slot). 4-way associativity needs ~2x entries to
/// avoid thrashing. The result is clamped between an 8 MiB floor and
/// `configured_max` ceiling. When `configured_max` is below the 8 MiB
/// floor, the floor is reduced to `configured_max` so the clamp range
/// remains valid.
pub(super) fn auto_tree_delta_cache_bytes(object_count: u32, configured_max: u32) -> u32 {
    let estimated_trees = (object_count as u64).saturating_mul(15) / 100;
    let estimated_bytes = estimated_trees.saturating_mul(4096 * 2);

    let min_cache = 8 * 1024 * 1024_u64; // 8 MiB floor
    let max_cache = configured_max as u64;
    let effective_min_cache = min_cache.min(max_cache);
    estimated_bytes.clamp(effective_min_cache, max_cache) as u32
}

/// Estimate a raw pack cache size from mapped pack bytes.
///
/// Returns `clamp(total_used_bytes / PACK_CACHE_FRACTION_DENOM, base, PACK_CACHE_MAX_BYTES)`.
/// Only packs referenced by `used_pack_ids` contribute to `total_used_bytes`.
/// Returns `base` unchanged when no used packs are mapped (e.g. loose-only
/// repos).
///
/// This is the *raw* estimate before per-worker and total-memory capping.
/// Prefer [`per_worker_cache_bytes`] in pipeline code to respect aggregate
/// memory limits.
pub(super) fn estimate_pack_cache_bytes(
    base: usize,
    pack_mmaps: &[Option<Mmap>],
    used_pack_ids: &[u16],
) -> usize {
    let total_bytes: u64 = used_pack_ids
        .iter()
        .filter_map(|id| pack_mmaps.get(*id as usize).and_then(|m| m.as_ref()))
        .map(|m| m.len() as u64)
        .sum();

    if total_bytes == 0 {
        return base;
    }

    let target = total_bytes / PACK_CACHE_FRACTION_DENOM;
    let target = target.min(PACK_CACHE_MAX_BYTES).max(base as u64);
    target as usize
}

/// Compute bounded per-worker pack cache bytes.
///
/// 1. Starts from the raw estimate ([`estimate_pack_cache_bytes`]).
/// 2. Caps at `PACK_CACHE_TOTAL_MAX_BYTES / workers` so aggregate memory
///    across all workers stays bounded (16 GiB by default).
/// 3. Floors at `PACK_CACHE_PER_WORKER_MIN` (32 MiB) so each worker
///    retains a functional cache.
/// 4. Clamps to `PACK_CACHE_MAX_BYTES` (2 GiB per-worker hard cap).
///
/// Step 3 can exceed the per-worker cap from step 2 — this is intentional:
/// a worker with too little cache degrades hit-rate more than marginally
/// exceeding the aggregate target.
///
/// Both scan pipelines should call this instead of
/// `estimate_pack_cache_bytes` directly.
pub(super) fn per_worker_cache_bytes(
    base: usize,
    pack_mmaps: &[Option<Mmap>],
    used_pack_ids: &[u16],
    workers: usize,
) -> usize {
    let raw = estimate_pack_cache_bytes(base, pack_mmaps, used_pack_ids);
    let workers = workers.max(1) as u64;

    // Cap: total memory across all workers must not exceed PACK_CACHE_TOTAL_MAX_BYTES.
    let per_worker_cap = PACK_CACHE_TOTAL_MAX_BYTES / workers;
    let target = (raw as u64).min(per_worker_cap);

    // Floor: each worker needs at least a minimal functional cache.
    let target = target.max(PACK_CACHE_PER_WORKER_MIN);

    // Hard per-worker ceiling.
    let target = target.min(PACK_CACHE_MAX_BYTES);

    target as usize
}

/// Load the MIDX view for the repository.
///
/// The parser uses the repo's object format to validate OID lengths.
///
/// # Preconditions
///
/// `acquire_midx` must have been called to populate `repo.mmaps.midx`.
///
/// # Errors
///
/// Returns `GitScanError::Midx` if the MIDX bytes are missing or corrupted.
pub(super) fn load_midx(repo: &RepoJobState) -> Result<MidxView<'_>, GitScanError> {
    let midx_bytes = repo
        .mmaps
        .midx
        .as_ref()
        .ok_or_else(|| GitScanError::Midx(MidxError::corrupt("midx bytes missing")))?;
    Ok(MidxView::parse(midx_bytes.as_slice(), repo.object_format)?)
}

/// Convert the repo start set into finalize [`RefEntry`] values.
///
/// The "start set" is the set of branch/tag tips that the walk begins from
/// (populated during repo discovery). Each entry's ref name is resolved
/// through the repo's shared name table so the resulting `RefEntry` vector
/// carries owned byte names suitable for the finalize stage.
pub(super) fn build_ref_entries(repo: &RepoJobState) -> Vec<RefEntry> {
    let mut refs = Vec::with_capacity(repo.start_set.len());
    for r in &repo.start_set {
        refs.push(RefEntry {
            ref_name: repo.ref_names.get(r.name).to_vec(),
            tip_oid: r.tip,
        });
    }
    refs
}

/// Memory-map pack files for zero-copy decoding.
///
/// Only packs whose IDs appear in `used_pack_ids` are mapped; the returned
/// vector has the same length as `pack_paths` with `None` for unmapped slots,
/// preserving pack-ID-to-index correspondence.
///
/// # Preconditions
///
/// `used_pack_ids` must be de-duplicated. Duplicates would double-count
/// mapped bytes against `limits.max_total_bytes` and re-map the same file.
///
/// # Errors
///
/// - `GitScanError::ResourceLimit` — pack count or cumulative file size
///   exceeds `limits`.
/// - `GitScanError::PackPlan(PackIdOutOfRange)` — a pack ID falls outside
///   `pack_paths`.
/// - `GitScanError::Io` — file metadata or mmap syscall failure.
pub(super) fn mmap_pack_files(
    pack_paths: &[PathBuf],
    used_pack_ids: &[u16],
    limits: PackMmapLimits,
) -> Result<Vec<Option<Mmap>>, GitScanError> {
    limits.validate();
    if used_pack_ids.len() > limits.max_open_packs as usize {
        return Err(GitScanError::ResourceLimit(format!(
            "pack count {} exceeds limit {}",
            used_pack_ids.len(),
            limits.max_open_packs
        )));
    }

    let mut out = Vec::with_capacity(pack_paths.len());
    out.resize_with(pack_paths.len(), || None);
    let mut total_bytes = 0_u64;
    for &pack_id in used_pack_ids {
        let idx = pack_id as usize;
        let path =
            pack_paths
                .get(idx)
                .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
                    pack_id,
                    pack_count: pack_paths.len(),
                }))?;
        let metadata = fs::metadata(path)?;
        total_bytes = total_bytes.saturating_add(metadata.len());
        if total_bytes > limits.max_total_bytes {
            return Err(GitScanError::ResourceLimit(format!(
                "mapped pack bytes {} exceed limit {}",
                total_bytes, limits.max_total_bytes
            )));
        }
        let file = File::open(path)?;
        // SAFETY: mapping read-only pack files. Two invariants relied on:
        // 1. The OS keeps the mapping valid even after `file` is dropped
        //    (the kernel holds its own file reference).
        // 2. Pack files are immutable after creation by git. Concurrent
        //    gc/repack may delete and recreate them, but we hold an open
        //    fd so the inode remains valid for the lifetime of the mmap.
        let mmap = unsafe { Mmap::map(&file)? };
        advise_sequential(&file, &mmap);
        out[idx] = Some(mmap);
    }
    Ok(out)
}

/// Hint to the OS that the pack mmap will be read sequentially.
///
/// Issues `POSIX_FADV_SEQUENTIAL` (Linux only) on the file descriptor and
/// `MADV_SEQUENTIAL` on the mapped region. Both are advisory; failures are
/// silently ignored since they only affect readahead heuristics.
///
/// # Safety (internal)
///
/// The `unsafe` block calls `libc::posix_fadvise` and `libc::madvise` with
/// valid file descriptors and mmap pointers that remain live for the
/// duration of the call. Both functions are idempotent advisory hints —
/// return codes are intentionally discarded.
#[cfg(unix)]
pub(super) fn advise_sequential(file: &File, reader: &Mmap) {
    // SAFETY: `file` is a valid open fd and `reader` is a live mmap.
    // Both libc calls are advisory hints; invalid arguments are harmless.
    unsafe {
        #[cfg(target_os = "linux")]
        let _ = libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        #[cfg(not(target_os = "linux"))]
        let _ = file;
        let _ = libc::madvise(
            reader.as_ptr() as *mut libc::c_void,
            reader.len(),
            libc::MADV_SEQUENTIAL,
        );
    }
}

#[cfg(not(unix))]
pub(super) fn advise_sequential(_file: &File, _reader: &Mmap) {}

/// Parse pack headers into `PackView`s used for planning.
///
/// Each pack view validates header structure and captures offsets needed by
/// the planning stage.
///
/// `pack_mmaps` may include `None` for unused packs; the output preserves that
/// indexing so pack IDs remain stable.
pub(super) fn build_pack_views<'a>(
    pack_mmaps: &'a [Option<Mmap>],
    format: ObjectFormat,
) -> Result<Vec<Option<PackView<'a>>>, GitScanError> {
    let mut views = Vec::with_capacity(pack_mmaps.len());
    for mmap in pack_mmaps {
        if let Some(mmap) = mmap {
            let view = PackView::parse(mmap.as_ref(), format.oid_len())
                .map_err(|err| GitScanError::PackPlan(PackPlanError::PackParse(err)))?;
            views.push(Some(view));
        } else {
            views.push(None);
        }
    }
    Ok(views)
}

/// Returns `(total_delta_deps, max_deps_in_single_plan)` across all plans.
///
/// Delta deps are pack entries that require decoding another object first
/// (the "base"). High dependency counts penalize sharding because shard
/// boundaries can separate a delta from its base, forcing cross-shard
/// resolution. The pipeline records these numbers in the run summary for
/// diagnostics. Strategy selection ([`select_pack_exec_strategy`]) computes
/// its own per-plan cost hints independently.
pub(super) fn summarize_pack_plan_deps(plans: &[PackPlan]) -> (u64, u32) {
    let mut total = 0u64;
    let mut max = 0u32;
    for plan in plans {
        let len = plan.delta_deps.len() as u32;
        total = total.saturating_add(len as u64);
        if len > max {
            max = len;
        }
    }
    (total, max)
}

// Sharding heuristic thresholds — these parameterize `select_plan_shard_count`
// and `select_pack_exec_strategy`. Each constant represents one independent
// cap; the shard count is the *minimum* across all of them.

/// Minimum decoded offsets before multi-threaded pack exec is considered.
const MIN_TOTAL_NEED_FOR_PARALLEL: usize = 512;
/// Minimum decoded offsets per shard to avoid oversharding tiny plans.
const MIN_NEED_PER_SHARD: usize = 1_024;
/// Minimum offset span per shard to avoid over-partitioning narrow ranges.
const MIN_SPAN_PER_SHARD: u64 = 4 * 1024 * 1024;
/// Cap shard fan-out when dependency pressure is high.
const MAX_SHARDS_WITH_DEP_PRESSURE: usize = 2;
/// Locality cap target: allow at most this percent of offset deps to cross shard boundaries.
const MAX_LOCALITY_CROSS_PERCENT: usize = 55;
/// Minimum offset-dependency sample size before locality pressure can reduce shards.
const MIN_LOCALITY_DEP_SAMPLES: usize = 128;

/// Stats-free cost hint derived from core `PackPlan` structure.
///
/// This intentionally avoids `plan.stats` so strategy selection remains
/// independent of optional perf/debug instrumentation surfaces. The hint
/// captures only structural properties visible from `need_offsets` and
/// `delta_deps`, which are sufficient for shard-count and strategy decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlanCostHint {
    /// Pack index this plan targets.
    pack_id: u16,
    /// Number of offsets that need decoding (`plan.need_offsets.len()`).
    need_count: usize,
    /// Byte span from first to last need offset; drives minimum-span-per-shard.
    span_bytes: u64,
    /// Delta deps where the base offset is *after* the dependent offset.
    /// Forward deps penalize sharding because a shard boundary could place
    /// a base in a different shard from its dependent.
    forward_deps: usize,
    /// Delta deps resolved via external OID lookup (not by offset).
    external_deps: usize,
}

/// Cross-shard locality pressure estimate for one plan at a candidate shard count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LocalityPressure {
    /// Count of offset-based delta deps examined (`BaseLoc::Offset`).
    offset_deps: usize,
    /// Offset deps where base/dependent would land in different shards.
    cross_shard_offset_deps: usize,
    /// Offset deps whose base offset was not found in `need_offsets`.
    unresolved_offset_bases: usize,
}

/// Diff-history pack execution strategy for a planned pack set.
///
/// Selected by [`select_pack_exec_strategy`] from worker count and per-plan
/// structural hints derived from `PackPlan` internals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PackExecStrategy {
    /// Single-threaded execution. Used when `workers <= 1` or no plans exist.
    Serial,
    /// One plan per worker with deterministic sequence reassembly.
    /// Chosen when `plan_count >= workers`.
    PackParallel,
    /// Intra-pack index sharding with per-pack shard count assignments.
    IntraPackSharded {
        /// `(pack_id, shard_count)` assignments for plans selected for sharding.
        shard_counts: Vec<(u16, usize)>,
    },
}

/// Extract a [`PlanCostHint`] from a plan's structural fields.
///
/// Counts forward delta dependencies (base offset > dependent offset) and
/// external dependencies (resolved by OID, not offset). These counts feed
/// the shard-count heuristic: high dependency pressure caps the number of
/// shards to avoid cross-shard decode ordering issues.
fn build_plan_cost_hint(plan: &PackPlan) -> PlanCostHint {
    let mut forward_deps = 0usize;
    let mut external_deps = 0usize;
    for dep in &plan.delta_deps {
        match dep.base {
            BaseLoc::Offset(base_offset) => {
                if base_offset > dep.offset {
                    forward_deps = forward_deps.saturating_add(1);
                }
            }
            BaseLoc::External { .. } => {
                external_deps = external_deps.saturating_add(1);
            }
        }
    }

    let span_bytes = plan
        .need_offsets
        .first()
        .zip(plan.need_offsets.last())
        .map_or(0, |(start, end)| end.saturating_sub(*start));

    PlanCostHint {
        pack_id: plan.pack_id,
        need_count: plan.need_offsets.len(),
        span_bytes,
        forward_deps,
        external_deps,
    }
}

/// Maps execution position to shard id using the same partitioning as [`shard_ranges`].
///
/// The partitioning distributes `len` items across `shards` with sizes differing
/// by at most 1. The first `extra = len % shards` shards get `base + 1` items;
/// the remaining shards get `base = len / shards` items. This creates two
/// contiguous regions:
///
/// - **Large prefix** (positions `0..extra*(base+1)`): shards of size `base+1`.
/// - **Small suffix** (positions after that): shards of size `base`.
///
/// The branch selects the correct region and divides to find the shard index.
/// Verified by Kani proof [`shard_id_partitions_cover_all_positions`].
#[inline(always)]
fn shard_id_for_exec_position(pos: usize, len: usize, shards: usize) -> usize {
    debug_assert!(len > 0);
    debug_assert!(shards > 0);
    debug_assert!(shards <= len);
    debug_assert!(pos < len);
    let base = len / shards;
    let extra = len % shards;
    // Boundary between the large-prefix region and the small-suffix region.
    let large_prefix_len = (base + 1) * extra;
    if pos < large_prefix_len {
        pos / (base + 1)
    } else {
        extra + (pos - large_prefix_len) / base
    }
}

/// Build the inverse map from need-index → execution position.
///
/// When `exec_order` is present, the execution order differs from need-offset
/// order (e.g. to decode bases before their dependents). Without it,
/// need-index *is* the execution position and `None` is returned.
fn build_exec_pos_by_need(plan: &PackPlan) -> Option<Vec<usize>> {
    let need_count = plan.need_offsets.len();
    plan.exec_order.as_ref().map(|order| {
        let mut pos = vec![usize::MAX; need_count];
        for (exec_pos, &need_idx_u32) in order.iter().enumerate() {
            let need_idx = need_idx_u32 as usize;
            if need_idx < need_count {
                pos[need_idx] = exec_pos;
            }
        }
        pos
    })
}

/// Estimate cross-shard dependency pressure for a proposed shard count.
///
/// Uses execution positions (natural order or `exec_order`) and counts how
/// many offset-based deps would cross shard boundaries under contiguous shard
/// partitioning.
///
/// The algorithm:
/// 1. Use the inverse map from need-index → execution position (identity when
///    no explicit `exec_order` exists).
/// 2. For each offset-based delta dep, resolve both the dependent and its base
///    to execution positions, then check whether they fall in different shards.
/// 3. Count crossings and unresolved bases (where the base offset isn't in
///    `need_offsets`, meaning it's decoded on-demand rather than planned).
///
/// `exec_pos_by_need` should be built once via [`build_exec_pos_by_need`] and
/// reused across calls with varying `shards` for the same plan.
fn estimate_locality_pressure(
    plan: &PackPlan,
    shards: usize,
    exec_pos_by_need: Option<&[usize]>,
) -> LocalityPressure {
    let need_count = plan.need_offsets.len();
    if need_count <= 1 || shards <= 1 {
        return LocalityPressure::default();
    }
    let shards = shards.max(1).min(need_count);

    let position_for_need_idx = |need_idx: usize| -> Option<usize> {
        if let Some(pos) = exec_pos_by_need {
            let exec_pos = *pos.get(need_idx)?;
            (exec_pos != usize::MAX).then_some(exec_pos)
        } else {
            Some(need_idx)
        }
    };

    let mut pressure = LocalityPressure::default();
    for (need_idx, &dep_idx_u32) in plan.delta_dep_index.iter().enumerate() {
        if dep_idx_u32 == NONE_U32 {
            continue;
        }
        let Some(dep) = plan.delta_deps.get(dep_idx_u32 as usize) else {
            continue;
        };
        let base_offset = match &dep.base {
            BaseLoc::Offset(base_offset) => *base_offset,
            BaseLoc::External { .. } => continue,
        };
        pressure.offset_deps = pressure.offset_deps.saturating_add(1);
        let Ok(base_need_idx) = plan.need_offsets.binary_search(&base_offset) else {
            pressure.unresolved_offset_bases = pressure.unresolved_offset_bases.saturating_add(1);
            continue;
        };
        let Some(dep_pos) = position_for_need_idx(need_idx) else {
            pressure.unresolved_offset_bases = pressure.unresolved_offset_bases.saturating_add(1);
            continue;
        };
        let Some(base_pos) = position_for_need_idx(base_need_idx) else {
            pressure.unresolved_offset_bases = pressure.unresolved_offset_bases.saturating_add(1);
            continue;
        };
        if shard_id_for_exec_position(dep_pos, need_count, shards)
            != shard_id_for_exec_position(base_pos, need_count, shards)
        {
            pressure.cross_shard_offset_deps = pressure.cross_shard_offset_deps.saturating_add(1);
        }
    }

    pressure
}

/// Reduce shard fan-out when contiguous shards would fragment many delta edges.
///
/// The cap is lowered deterministically until weighted cross-shard pressure
/// (crossings + 2× unresolved bases) falls below
/// [`MAX_LOCALITY_CROSS_PERCENT`], or until
/// [`MAX_SHARDS_WITH_DEP_PRESSURE`] is reached.
fn apply_locality_shard_cap(plan: &PackPlan, shard_cap: usize) -> usize {
    let mut cap = shard_cap.max(1).min(plan.need_offsets.len());
    // Build the inverse map once and reuse across iterations instead of
    // allocating a fresh vec on every call to estimate_locality_pressure.
    let exec_pos = build_exec_pos_by_need(plan);
    while cap > MAX_SHARDS_WITH_DEP_PRESSURE {
        let pressure = estimate_locality_pressure(plan, cap, exec_pos.as_deref());
        if pressure.offset_deps < MIN_LOCALITY_DEP_SAMPLES {
            break;
        }
        // Unresolved bases are weighted 2× because they force expensive
        // cross-pack or loose-object fallback I/O, whereas a resolved
        // cross-shard dep only causes a cache miss within the same pack.
        let weighted_cross = pressure
            .cross_shard_offset_deps
            .saturating_add(pressure.unresolved_offset_bases.saturating_mul(2));
        if weighted_cross.saturating_mul(100)
            <= pressure
                .offset_deps
                .saturating_mul(MAX_LOCALITY_CROSS_PERCENT)
        {
            break;
        }
        cap -= 1;
    }
    cap
}

/// Select the shard count for one pack plan based on structural heuristics.
///
/// The shard count is the minimum of several independent caps:
/// 1. **Worker count** — never more shards than available workers.
/// 2. **`need_count / MIN_NEED_PER_SHARD`** — avoids oversharding tiny plans.
/// 3. **`span_bytes / MIN_SPAN_PER_SHARD`** — avoids splitting narrow byte ranges.
/// 4. **Dependency pressure** — if more than half the need offsets have forward
///    or external deps, the shard count is capped to [`MAX_SHARDS_WITH_DEP_PRESSURE`]
///    to reduce cross-shard ordering hazards.
/// 5. **Locality pressure** — if projected shard boundaries split too many
///    offset-based deps in execution order, reduce fan-out to improve cache locality.
///
/// Returns 1 for single-worker execution or degenerate plans (≤ 1 offset).
#[cfg(test)]
#[inline(always)]
pub(super) fn select_plan_shard_count(workers: usize, plan: &PackPlan) -> usize {
    select_plan_shard_count_with_hint(workers, plan, &build_plan_cost_hint(plan))
}

/// [`select_plan_shard_count`] variant that accepts a pre-computed hint.
///
/// Use this when the caller has already computed [`PlanCostHint`] (e.g. inside
/// [`select_pack_exec_strategy`]) to avoid redundant iteration over `delta_deps`.
#[inline(always)]
fn select_plan_shard_count_with_hint(
    workers: usize,
    plan: &PackPlan,
    hint: &PlanCostHint,
) -> usize {
    let workers = workers.max(1);
    if workers == 1 {
        return 1;
    }

    if hint.need_count <= 1 {
        return 1;
    }

    let mut shard_cap = workers.min(hint.need_count);
    let by_need = hint.need_count / MIN_NEED_PER_SHARD;
    shard_cap = if by_need == 0 {
        1
    } else {
        shard_cap.min(by_need.max(1))
    };

    if hint.span_bytes > 0 {
        let by_span = (hint.span_bytes / MIN_SPAN_PER_SHARD) as usize;
        shard_cap = if by_span == 0 {
            1
        } else {
            shard_cap.min(by_span.max(1))
        };
    }

    let dep_pressure = hint.forward_deps.saturating_add(hint.external_deps);
    if dep_pressure > (hint.need_count / 2) {
        shard_cap = shard_cap.min(MAX_SHARDS_WITH_DEP_PRESSURE);
    }

    shard_cap = apply_locality_shard_cap(plan, shard_cap);

    shard_cap.max(1).min(hint.need_count)
}

/// Returns assigned shard count for `pack_id` or `1` if not present.
#[inline(always)]
pub(super) fn shard_count_for_pack(shard_counts: &[(u16, usize)], pack_id: u16) -> usize {
    shard_counts
        .iter()
        .find_map(|(id, shards)| (*id == pack_id).then_some(*shards))
        .unwrap_or(1)
        .max(1)
}

/// Select diff-history pack execution strategy from workers and plan structure.
///
/// Decision boundaries:
/// - `workers <= 1` or `plans == 0` → [`PackExecStrategy::Serial`]
/// - tiny total decode work → [`PackExecStrategy::Serial`]
/// - `plans >= workers` → [`PackExecStrategy::PackParallel`]
/// - otherwise → [`PackExecStrategy::IntraPackSharded`] with adaptive shards
#[inline(always)]
pub(super) fn select_pack_exec_strategy(workers: usize, plans: &[PackPlan]) -> PackExecStrategy {
    let workers = workers.max(1);
    if workers == 1 || plans.is_empty() {
        return PackExecStrategy::Serial;
    }

    // Compute hints once — reused for both the total-need check and per-plan
    // shard count selection, avoiding redundant delta_deps iteration.
    let hints: Vec<PlanCostHint> = plans.iter().map(build_plan_cost_hint).collect();
    let total_need: usize = hints.iter().map(|h| h.need_count).sum();
    if total_need < MIN_TOTAL_NEED_FOR_PARALLEL {
        return PackExecStrategy::Serial;
    }

    if plans.len() >= workers {
        PackExecStrategy::PackParallel
    } else {
        let mut shard_counts = Vec::with_capacity(plans.len());
        for (plan, hint) in plans.iter().zip(&hints) {
            shard_counts.push((
                plan.pack_id,
                select_plan_shard_count_with_hint(workers, plan, hint),
            ));
        }
        PackExecStrategy::IntraPackSharded { shard_counts }
    }
}

/// Returns execution indices in deterministic order for a plan.
///
/// When `exec_order` is present (set by the planner when forward delta
/// dependencies exist) it is used to decode bases before their dependents.
/// Otherwise offsets are visited in natural `need_offsets` order, which is
/// correct when all bases precede their deltas in the pack file.
pub(super) fn build_exec_indices(plan: &PackPlan) -> Vec<usize> {
    if let Some(order) = plan.exec_order.as_ref() {
        order.iter().map(|&idx| idx as usize).collect()
    } else {
        (0..plan.need_offsets.len()).collect()
    }
}

/// Split `[0, len)` into `shards` contiguous `(start, end)` ranges.
///
/// The first `len % shards` ranges receive one extra element to distribute
/// remainder evenly. Returns an empty vec when `len == 0`.
/// `shards` is clamped to `[1, len]`.
///
/// Example: `shard_ranges(10, 3)` → `[(0,4), (4,7), (7,10)]`.
pub(super) fn shard_ranges(len: usize, shards: usize) -> Vec<(usize, usize)> {
    if len == 0 {
        return Vec::new();
    }
    let shards = shards.max(1).min(len);
    let base = len / shards;
    let extra = len % shards;
    let mut out = Vec::with_capacity(shards);
    let mut start = 0usize;
    for idx in 0..shards {
        let mut end = start + base;
        if idx < extra {
            end += 1;
        }
        out.push((start, end));
        start = end;
    }
    out
}

/// Merge per-shard scan results into a single [`ScannedBlobs`].
///
/// Each blob stores its findings as a [`FindingSpan`] (`start` + `len`)
/// into the flat `finding_arena`. When arenas are concatenated the `start`
/// indices become stale, so every blob's `findings.start` is shifted
/// ("rebased") by the arena length at the time its shard is appended.
/// The `len` field is unaffected because it is relative to `start`.
///
/// Shards must be in deterministic order (e.g. by pack id) to produce
/// reproducible output.
pub(super) fn merge_scanned_blobs(mut shards: Vec<ScannedBlobs>) -> ScannedBlobs {
    let total_blobs: usize = shards.iter().map(|s| s.blobs.len()).sum();
    let total_findings: usize = shards.iter().map(|s| s.finding_arena.len()).sum();

    let mut merged = ScannedBlobs {
        blobs: Vec::with_capacity(total_blobs),
        finding_arena: Vec::with_capacity(total_findings),
    };

    for shard in shards.drain(..) {
        let base = merged.finding_arena.len() as u32;
        merged.finding_arena.extend_from_slice(&shard.finding_arena);
        for mut blob in shard.blobs {
            blob.findings.start = blob.findings.start.saturating_add(base);
            merged.blobs.push(blob);
        }
    }

    merged
}

/// Append `src` blobs into `dst`, rebasing [`FindingSpan::start`] into `dst`'s arena.
///
/// Same rebasing logic as [`merge_scanned_blobs`] but operates in-place.
pub(super) fn append_scanned_blobs(dst: &mut ScannedBlobs, mut src: ScannedBlobs) {
    let base = dst.finding_arena.len() as u32;
    dst.finding_arena.extend_from_slice(&src.finding_arena);
    for mut blob in src.blobs.drain(..) {
        blob.findings.start = blob.findings.start.saturating_add(base);
        dst.blobs.push(blob);
    }
}

/// Output produced by one scheduler-dispatched pack-plan task.
///
/// All fields correspond to the same plan (or shard of a plan).
/// The caller reassembles outputs in deterministic sequence order
/// regardless of worker completion order.
pub(super) struct SchedulerPackExecOutput {
    /// Pack execution report for this plan (decode stats, timing).
    pub report: PackExecReport,
    /// Scanned blobs with findings. Finding arena offsets are local to this
    /// output and must be rebased when merged with other outputs.
    pub scanned: ScannedBlobs,
    /// Candidate-level skip records mapped from pack skip offsets.
    pub skipped: Vec<SkippedCandidate>,
    /// Always-on summary counters for this output shard/plan.
    pub common_metrics: GitScanCommonMetrics,
}

/// Task dispatched to a scheduler worker thread.
///
/// Variant determines which execution function is called in
/// [`run_scheduler_pack_task`]. The `seq` / index fields are positions
/// into the shared `plans` vector, not pack IDs.
enum SchedulerPackTask {
    /// Execute a full pack plan (used by Serial and PackParallel strategies).
    ///
    /// `seq` is the index into `shared.plans` and doubles as the output
    /// slot index for deterministic reassembly.
    ExecPlan { seq: usize },
    /// Execute one shard of a pack plan (used by IntraPackSharded strategy).
    ///
    /// `plan_idx` indexes `shared.plans`; `shard_idx` indexes the
    /// `shard_ranges` within that plan's [`SchedulerShardMeta`].
    ExecShard { plan_idx: usize, shard_idx: usize },
}

/// Per-worker scratch space reused across tasks to avoid re-allocation.
///
/// Created once per worker thread by the `Executor` init closure.
/// Fields grow to steady-state capacity after the first few tasks
/// and remain stable for the rest of the scan.
struct SchedulerPackScratch {
    /// Tiered set-associative CLOCK delta base cache sized by [`per_worker_cache_bytes`].
    cache: PackCache,
    /// Decode workspace: inflate buffer, delta apply buffer, object staging.
    exec_scratch: PackExecScratch,
    /// Lazily initialized heavy worker-local runtime (I/O + adapter state).
    runtime: Option<SchedulerPackWorkerRuntime>,
}

/// Heavy scheduler worker state reused across all tasks on one thread.
///
/// This caches the expensive one-time setup that used to be rebuilt per task:
/// parsed MIDX + `PackIo` and `EngineAdapter` wiring.
///
/// # Safety
///
/// `adapter` and `external` hold transmuted `'static` references that actually
/// borrow from `_engine` and `_midx_bytes` respectively. They are wrapped in
/// [`ManuallyDrop`] so they are NOT dropped by the compiler's automatic field
/// drop order. Instead, our custom [`Drop`] impl explicitly drops borrowers
/// before their backing storage.
///
/// # Safety Invariant
///
/// Field declaration order is load-bearing for soundness. The `Drop` impl
/// (below) explicitly drops `adapter` and `external` (the borrowers) before
/// the compiler's automatic drop runs on `_engine` and `_midx_bytes` (the
/// owners). Reordering fields, adding borrowing fields, or removing the
/// `ManuallyDrop` wrappers will create use-after-free.
///
/// Dependency chain:
///   `adapter` borrows `_engine`    → drop adapter first
///   `external` borrows `_midx_bytes` → drop external first
#[repr(C)]
struct SchedulerPackWorkerRuntime {
    // Borrowing fields — dropped explicitly in our `Drop` impl before
    // the owning storage they reference.
    adapter: ManuallyDrop<EngineAdapter<'static>>,
    external: ManuallyDrop<PackIo<'static>>,
    // Owning storage — dropped automatically after our `Drop` impl runs.
    _engine: Arc<Engine>,
    _midx_bytes: BytesView,
}

impl Drop for SchedulerPackWorkerRuntime {
    fn drop(&mut self) {
        // SAFETY: `adapter` holds a transmuted `&'static Engine` that actually
        // borrows from `_engine`, and `external` holds a transmuted
        // `MidxView<'static>` that actually borrows from `_midx_bytes`.
        // We must drop the borrowers before the backing storage is freed.
        // After this function returns, the remaining fields (`_engine`,
        // `_midx_bytes`) are dropped automatically in declaration order.
        unsafe {
            ManuallyDrop::drop(&mut self.adapter);
            ManuallyDrop::drop(&mut self.external);
        }
    }
}

// Compile-time enforcement: borrowing fields must precede owning fields
// in declaration order. Catches accidental field reordering that would
// create use-after-free (the custom Drop impl drops borrowers first).
const _: () = {
    assert!(
        std::mem::offset_of!(SchedulerPackWorkerRuntime, adapter)
            < std::mem::offset_of!(SchedulerPackWorkerRuntime, _engine),
        "adapter (borrower) must be declared before _engine (owner)"
    );
    assert!(
        std::mem::offset_of!(SchedulerPackWorkerRuntime, external)
            < std::mem::offset_of!(SchedulerPackWorkerRuntime, _midx_bytes),
        "external (borrower) must be declared before _midx_bytes (owner)"
    );
};

/// Scheduler execution representation for one plan's shardable decode order.
#[derive(Clone)]
enum SchedulerShardExecPlan {
    /// Natural order `need_offsets[start..end)`.
    Natural { len: usize },
    /// Explicit execution permutation (`exec_order`) by need index.
    Explicit(Vec<usize>),
}

impl SchedulerShardExecPlan {
    #[inline(always)]
    fn len(&self) -> usize {
        match self {
            Self::Natural { len } => *len,
            Self::Explicit(indices) => indices.len(),
        }
    }
}

/// Build shard execution representation for one plan.
#[inline(always)]
fn build_scheduler_shard_exec_plan(plan: &PackPlan) -> SchedulerShardExecPlan {
    if plan.exec_order.is_some() {
        SchedulerShardExecPlan::Explicit(build_exec_indices(plan))
    } else {
        SchedulerShardExecPlan::Natural {
            len: plan.need_offsets.len(),
        }
    }
}

/// Pre-computed sharding metadata for one pack plan.
///
/// Built once before task dispatch and shared (read-only) across all shard
/// tasks for the same plan. `exec_plan` defines decode ordering and
/// `shard_ranges` partitions that order into contiguous slices, one per shard.
#[derive(Clone)]
struct SchedulerShardMeta {
    exec_plan: SchedulerShardExecPlan,
    /// Precomputed once per plan and shared by all shards.
    plan_hot_deps: PackPlanHotDeps,
    /// Per-offset candidate ranges for explicit exec-order sharding.
    candidate_ranges: Vec<CandidateRange>,
    /// `(start, end)` slices into `exec_plan`.
    shard_ranges: Vec<(usize, usize)>,
}

/// Immutable state shared across all scheduler worker threads.
///
/// Wrapped in `Arc` so each worker can borrow without lifetime issues.
/// Mutable per-worker state lives in [`SchedulerPackScratch`] instead.
///
/// Fields fall into three categories:
/// - **I/O context** — mmaps, paths, MIDX bytes for pack/loose decode.
/// - **Scan context** — engine, adapter config, decode limits.
/// - **Event context** — sink, commit-graph, bitset for `CommitMeta` gating.
struct SchedulerPackShared {
    engine: Arc<Engine>,
    event_sink: Arc<dyn EventSink>,
    midx_bytes: BytesView,
    object_format: ObjectFormat,
    pack_paths: Arc<Vec<PathBuf>>,
    loose_dirs: Arc<Vec<PathBuf>>,
    pack_mmaps: Arc<Vec<Option<Mmap>>>,
    path_arena: ByteArena,
    spill_dir: PathBuf,
    pack_decode: PackDecodeLimits,
    pack_io: PackIoLimits,
    adapter_cfg: EngineAdapterConfig,
    plans: Vec<PackPlan>,
    shard_meta: Option<Vec<SchedulerShardMeta>>,
    /// Commit-graph index for resolving `commit_id` → OID + timestamp.
    /// Cloned into each worker's `EngineAdapter` for `CommitMeta` emission.
    commit_graph: Arc<super::commit_graph::CommitGraphIndex>,
    /// Emit-once bitset shared across all worker `EngineAdapter` instances
    /// so each `commit_id` produces at most one `CommitMeta` event.
    commit_meta_seen: Arc<gossip_stdx::AtomicBitSet>,
}

/// Pre-allocate adapter result capacity for a shard's execution slice.
///
/// Sums the candidate counts across all offsets in `exec_slice` so the
/// adapter can reserve a single contiguous allocation before the decode
/// loop, avoiding incremental growth on the hot path.
fn reserve_results_for_exec_slice(
    adapter: &mut EngineAdapter<'_>,
    exec_slice: &[usize],
    candidate_ranges: &[CandidateRange],
) {
    let mut total = 0usize;
    for idx in exec_slice {
        if let Some((start, end)) = candidate_ranges
            .get(*idx)
            .copied()
            .and_then(CandidateRange::bounds)
        {
            total = total.saturating_add(end.saturating_sub(start));
        }
    }
    if total > 0 {
        adapter.reserve_results(total);
    }
}

/// Pre-allocate adapter result capacity for natural-order shard range.
///
/// Uses offset bounds to count candidates in `need_offsets[start..end)` without
/// materializing per-index candidate range tables.
fn reserve_results_for_need_range(
    adapter: &mut EngineAdapter<'_>,
    plan: &PackPlan,
    start: usize,
    end: usize,
) {
    if start >= end {
        return;
    }
    let first_offset = plan.need_offsets[start];
    let last_offset = plan.need_offsets[end - 1];
    let cand_start = plan
        .candidate_offsets
        .partition_point(|cand| cand.offset < first_offset);
    let cand_end = plan
        .candidate_offsets
        .partition_point(|cand| cand.offset <= last_offset);
    let total = cand_end.saturating_sub(cand_start);
    if total > 0 {
        adapter.reserve_results(total);
    }
}

/// Construct a zero-work output for plans with no executable offsets.
///
/// Used by the `IntraPackSharded` path when a plan has no decode work (empty
/// execution order), so every plan slot has a value for deterministic
/// reassembly without special-casing `None`.
fn empty_scheduler_output() -> SchedulerPackExecOutput {
    SchedulerPackExecOutput {
        report: PackExecReport::default(),
        scanned: ScannedBlobs {
            blobs: Vec::new(),
            finding_arena: Vec::new(),
        },
        skipped: Vec::new(),
        common_metrics: GitScanCommonMetrics::default(),
    }
}

/// Build reusable worker runtime for scheduler pack tasks.
///
/// This performs the fallible setup that historically happened per task. The
/// caller stores the returned runtime in worker scratch and reuses it.
///
/// # Safety
///
/// This function widens lifetimes for:
/// - `MidxView` (to keep a parsed view inside reusable `PackIo`)
/// - `&Engine` (to keep a reusable `EngineAdapter`)
///
/// Soundness relies on ownership stored in [`SchedulerPackWorkerRuntime`]:
/// `external` cannot outlive `_midx_bytes`, and `adapter` cannot outlive
/// `_engine`. Drop ordering is enforced by a custom `Drop` impl on the
/// runtime struct (borrowers are dropped before their backing storage).
fn build_scheduler_worker_runtime(
    shared: &SchedulerPackShared,
) -> Result<SchedulerPackWorkerRuntime, GitScanError> {
    let midx_bytes = shared.midx_bytes.clone();
    let midx = MidxView::parse(midx_bytes.as_slice(), shared.object_format)?;
    // SAFETY: Widens `midx` lifetime to `'static` to store in `SchedulerPackWorkerRuntime`.
    // Sound because `_midx_bytes` (owner) lives in the same struct and `external` (borrower)
    // is wrapped in `ManuallyDrop`. The custom `Drop` impl drops `external` before `_midx_bytes`.
    // Breaks if: field reordering, removing `ManuallyDrop`, or dropping `_midx_bytes` before `external`.
    // See `SchedulerPackWorkerRuntime` doc comment and `#[repr(C)]` guarantee.
    let midx: MidxView<'static> = unsafe { std::mem::transmute(midx) };
    let external = PackIo::from_parts(
        midx,
        (*shared.pack_paths).clone(),
        (*shared.loose_dirs).clone(),
        shared.pack_io,
    )
    .map_err(GitScanError::PackIo)?;

    let engine = Arc::clone(&shared.engine);
    // SAFETY: Widens `&Engine` lifetime to `'static` to create reusable `EngineAdapter`.
    // Sound because `_engine` (owner) lives in the same struct and `adapter` (borrower)
    // is wrapped in `ManuallyDrop`. The custom `Drop` impl drops `adapter` before `_engine`.
    // Breaks if: field reordering, removing `ManuallyDrop`, or dropping `_engine` before `adapter`.
    // See `SchedulerPackWorkerRuntime` doc comment and `#[repr(C)]` guarantee.
    let engine_ref: &'static Engine = unsafe { std::mem::transmute(engine.as_ref()) };
    let adapter = EngineAdapter::new_with_event_sink(
        engine_ref,
        shared.adapter_cfg,
        CommitMetaContext {
            event_sink: Arc::clone(&shared.event_sink),
            commit_graph_index: Arc::clone(&shared.commit_graph),
            commit_meta_seen: Arc::clone(&shared.commit_meta_seen),
            identity_interner: None,
        },
    );

    Ok(SchedulerPackWorkerRuntime {
        adapter: ManuallyDrop::new(adapter),
        external: ManuallyDrop::new(external),
        _engine: engine,
        _midx_bytes: midx_bytes,
    })
}

/// Ensure reusable worker runtime is initialized in scratch.
fn ensure_scheduler_worker_runtime(
    runtime: &mut Option<SchedulerPackWorkerRuntime>,
    shared: &SchedulerPackShared,
) -> Result<(), GitScanError> {
    if runtime.is_none() {
        *runtime = Some(build_scheduler_worker_runtime(shared)?);
    }
    Ok(())
}

/// Resolve a plan index from shared scheduler input.
#[inline(always)]
fn scheduler_plan_at(
    shared: &SchedulerPackShared,
    index: usize,
) -> Result<&PackPlan, GitScanError> {
    shared.plans.get(index).ok_or({
        GitScanError::PackExec(PackExecError::SchedulerPlanIndexOutOfRange {
            index,
            plan_count: shared.plans.len(),
        })
    })
}

/// Resolve a shard plan index from shared scheduler input.
#[inline(always)]
fn scheduler_shard_plan_at(
    shared: &SchedulerPackShared,
    plan_idx: usize,
) -> Result<&PackPlan, GitScanError> {
    shared.plans.get(plan_idx).ok_or({
        GitScanError::PackExec(PackExecError::SchedulerShardPlanIndexOutOfRange {
            plan_idx,
            plan_count: shared.plans.len(),
        })
    })
}

/// Resolve pack bytes for a plan from shared mapped packs.
#[inline(always)]
fn scheduler_pack_bytes<'a>(
    shared: &'a SchedulerPackShared,
    plan: &PackPlan,
) -> Result<&'a [u8], GitScanError> {
    let pack_id = plan.pack_id as usize;
    shared
        .pack_mmaps
        .get(pack_id)
        .and_then(|mmap| mmap.as_ref())
        .ok_or(GitScanError::PackPlan(PackPlanError::PackIdOutOfRange {
            pack_id: plan.pack_id,
            pack_count: shared.pack_mmaps.len(),
        }))
        .map(Mmap::as_ref)
}

/// Run task logic with initialized worker runtime and reusable scratch.
#[inline(always)]
fn with_scheduler_worker_parts<T>(
    scratch: &mut SchedulerPackScratch,
    shared: &SchedulerPackShared,
    mut f: impl FnMut(
        &mut PackCache,
        &mut PackExecScratch,
        &mut PackIo<'static>,
        &mut EngineAdapter<'static>,
    ) -> Result<T, GitScanError>,
) -> Result<T, GitScanError> {
    ensure_scheduler_worker_runtime(&mut scratch.runtime, shared)?;
    let runtime = scratch
        .runtime
        .as_mut()
        .expect("scheduler worker runtime initialized");
    runtime.adapter.clear_results();
    let adapter: &mut EngineAdapter<'static> = &mut runtime.adapter;
    let external: &mut PackIo<'static> = &mut runtime.external;
    f(
        &mut scratch.cache,
        &mut scratch.exec_scratch,
        external,
        adapter,
    )
}

/// Build scheduler task output from adapter-owned report/results/metrics.
#[inline(always)]
fn scheduler_pack_task_output(
    adapter: &mut EngineAdapter<'_>,
    report: PackExecReport,
) -> SchedulerPackExecOutput {
    let mut common_metrics = adapter.take_metrics();
    common_metrics.errors = common_metrics
        .errors
        .saturating_add(count_pack_exec_skip_errors(report.skips.as_slice()));
    SchedulerPackExecOutput {
        report,
        scanned: adapter.take_results(),
        skipped: Vec::new(),
        common_metrics,
    }
}

#[inline(always)]
fn count_pack_exec_skip_errors(skips: &[SkipRecord]) -> u64 {
    let mut errors = 0u64;
    for skip in skips {
        if skip.reason.is_error() {
            errors = errors.saturating_add(1);
        }
    }
    errors
}

/// Execute a single scheduler-dispatched pack task (plan or shard).
///
/// Uses reusable per-worker runtime (`PackIo` + `EngineAdapter`) from
/// `scratch`, creating it lazily on first use, then delegates to the
/// appropriate pack-exec function. The per-worker decode/cache scratch
/// is also reused across tasks on the same thread.
///
/// # Error propagation
///
/// Errors bubble up to the scheduler closure, which stores the first
/// error in `first_error` and sets the abort flag to quiesce remaining
/// tasks.
fn run_scheduler_pack_task(
    task: SchedulerPackTask,
    scratch: &mut SchedulerPackScratch,
    shared: &SchedulerPackShared,
) -> Result<SchedulerPackExecOutput, GitScanError> {
    with_scheduler_worker_parts(scratch, shared, |cache, exec_scratch, external, adapter| {
        let report = match task {
            SchedulerPackTask::ExecPlan { seq } => {
                let plan = scheduler_plan_at(shared, seq)?;
                let pack_bytes = scheduler_pack_bytes(shared, plan)?;
                adapter.reserve_results(plan.candidate_offsets.len());
                execute_pack_plan_with_scratch(
                    plan,
                    pack_bytes,
                    &shared.path_arena,
                    &shared.pack_decode,
                    cache,
                    external,
                    adapter,
                    &shared.spill_dir,
                    exec_scratch,
                )?
            }
            SchedulerPackTask::ExecShard {
                plan_idx,
                shard_idx,
            } => {
                let plan = scheduler_shard_plan_at(shared, plan_idx)?;
                let shard_meta = shared
                    .shard_meta
                    .as_ref()
                    .and_then(|meta| meta.get(plan_idx))
                    .ok_or({
                        GitScanError::PackExec(PackExecError::SchedulerShardMetadataMissing {
                            plan_idx,
                        })
                    })?;
                let (start, end) = *shard_meta.shard_ranges.get(shard_idx).ok_or({
                    GitScanError::PackExec(PackExecError::SchedulerShardIndexOutOfRange {
                        plan_idx,
                        shard_idx,
                        shard_count: shard_meta.shard_ranges.len(),
                    })
                })?;
                let pack_bytes = scheduler_pack_bytes(shared, plan)?;

                match &shard_meta.exec_plan {
                    SchedulerShardExecPlan::Explicit(exec_indices) => {
                        let exec_slice = &exec_indices[start..end];
                        reserve_results_for_exec_slice(
                            adapter,
                            exec_slice,
                            &shard_meta.candidate_ranges,
                        );
                        execute_pack_plan_with_scratch_indices_hot_deps(
                            plan,
                            pack_bytes,
                            &shared.path_arena,
                            &shared.pack_decode,
                            cache,
                            external,
                            adapter,
                            &shared.spill_dir,
                            exec_scratch,
                            exec_slice,
                            &shard_meta.candidate_ranges,
                            &shard_meta.plan_hot_deps,
                        )?
                    }
                    SchedulerShardExecPlan::Natural { .. } => {
                        reserve_results_for_need_range(adapter, plan, start, end);
                        execute_pack_plan_with_scratch_range_hot_deps(
                            plan,
                            pack_bytes,
                            &shared.path_arena,
                            &shared.pack_decode,
                            cache,
                            external,
                            adapter,
                            &shared.spill_dir,
                            exec_scratch,
                            start,
                            end,
                            &shard_meta.plan_hot_deps,
                        )?
                    }
                }
            }
        };
        Ok(scheduler_pack_task_output(adapter, report))
    })
}

struct SchedulerExecEnv {
    engine: Arc<Engine>,
    event_sink: Arc<dyn EventSink>,
    midx_bytes: BytesView,
    object_format: ObjectFormat,
    pack_paths: Arc<Vec<PathBuf>>,
    loose_dirs: Arc<Vec<PathBuf>>,
    pack_mmaps: Arc<Vec<Option<Mmap>>>,
    path_arena: Arc<ByteArena>,
    spill_dir: Arc<PathBuf>,
    pack_decode: PackDecodeLimits,
    pack_io: PackIoLimits,
    adapter_cfg: EngineAdapterConfig,
    pack_cache_bytes: u32,
    exec_workers: usize,
    pin_threads: bool,
    commit_graph: Arc<crate::commit_graph::CommitGraphIndex>,
    commit_meta_seen: Arc<gossip_stdx::AtomicBitSet>,
}

impl SchedulerExecEnv {
    #[inline(always)]
    fn executor_config(&self) -> ExecutorConfig {
        ExecutorConfig {
            workers: self.exec_workers,
            seed: 0x853c49e6748fea9b,
            pin_threads: self.pin_threads,
            ..ExecutorConfig::default()
        }
    }

    fn build_shared(
        &self,
        plans: Arc<Vec<PackPlan>>,
        shard_meta: Option<Arc<Vec<SchedulerShardMeta>>>,
    ) -> Arc<SchedulerPackShared> {
        Arc::new(SchedulerPackShared {
            engine: Arc::clone(&self.engine),
            event_sink: Arc::clone(&self.event_sink),
            midx_bytes: self.midx_bytes.clone(),
            object_format: self.object_format,
            pack_paths: Arc::clone(&self.pack_paths),
            loose_dirs: Arc::clone(&self.loose_dirs),
            pack_mmaps: Arc::clone(&self.pack_mmaps),
            path_arena: Arc::unwrap_or_clone(Arc::clone(&self.path_arena)),
            spill_dir: Arc::unwrap_or_clone(Arc::clone(&self.spill_dir)),
            pack_decode: self.pack_decode,
            pack_io: self.pack_io,
            adapter_cfg: self.adapter_cfg,
            plans: Arc::unwrap_or_clone(plans),
            shard_meta: shard_meta.map(Arc::unwrap_or_clone),
            commit_graph: Arc::clone(&self.commit_graph),
            commit_meta_seen: Arc::clone(&self.commit_meta_seen),
        })
    }
}

#[inline(always)]
fn scheduler_worker_scratch(pack_cache_bytes: u32) -> SchedulerPackScratch {
    SchedulerPackScratch {
        cache: PackCache::new(pack_cache_bytes),
        exec_scratch: PackExecScratch::default(),
        runtime: None,
    }
}

#[inline(always)]
fn store_scheduler_error(
    first_error: &Mutex<Option<GitScanError>>,
    abort_flag: &AtomicBool,
    err: GitScanError,
) {
    abort_flag.store(true, Ordering::Release);
    let mut guard = first_error
        .lock()
        .expect("scheduler pack error mutex poisoned");
    if guard.is_none() {
        *guard = Some(err);
    }
}

#[inline(always)]
fn take_scheduler_error(first_error: &Mutex<Option<GitScanError>>) -> Option<GitScanError> {
    first_error
        .lock()
        .expect("scheduler pack error mutex poisoned")
        .take()
}

#[inline(always)]
fn scheduler_queue_rejected_error(shard_queue: bool) -> GitScanError {
    GitScanError::PackExec(if shard_queue {
        PackExecError::SchedulerShardQueueRejected
    } else {
        PackExecError::SchedulerTaskQueueRejected
    })
}

fn collect_plan_outputs(
    plans: &[PackPlan],
    output_slots: &[Mutex<Option<SchedulerPackExecOutput>>],
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    let mut merged = Vec::with_capacity(plans.len());
    for (plan_idx, slot) in output_slots.iter().enumerate() {
        let mut output = slot
            .lock()
            .expect("scheduler pack output slot poisoned")
            .take()
            .ok_or({
                GitScanError::PackExec(PackExecError::SchedulerPlanOutputMissing { plan_idx })
            })?;
        // Defer skip mapping to merge time so worker tasks avoid building
        // per-task skipped vectors in the hot path.
        collect_skipped_candidates(&plans[plan_idx], &output.report.skips, &mut output.skipped);
        merged.push(output);
    }
    Ok(merged)
}

fn execute_plan_tasks(
    env: SchedulerExecEnv,
    plans: Arc<Vec<PackPlan>>,
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    let plan_count = plans.len();
    type OutputSlot = Mutex<Option<SchedulerPackExecOutput>>;
    let output_slots: Arc<Vec<OutputSlot>> =
        Arc::new((0..plan_count).map(|_| Mutex::new(None)).collect());
    let shared = env.build_shared(plans, None);
    let first_error: Arc<Mutex<Option<GitScanError>>> = Arc::new(Mutex::new(None));
    let abort_flag = Arc::new(AtomicBool::new(false));

    let pack_cache_bytes = env.pack_cache_bytes;
    let ex = Executor::<SchedulerPackTask>::new(
        env.executor_config(),
        move |_wid| scheduler_worker_scratch(pack_cache_bytes),
        {
            let shared = Arc::clone(&shared);
            let output_slots = Arc::clone(&output_slots);
            let first_error = Arc::clone(&first_error);
            let abort_flag = Arc::clone(&abort_flag);
            move |task, ctx: &mut WorkerCtx<SchedulerPackTask, SchedulerPackScratch>| {
                if abort_flag.load(Ordering::Acquire) {
                    return;
                }
                let seq = match task {
                    SchedulerPackTask::ExecPlan { seq } => seq,
                    SchedulerPackTask::ExecShard { .. } => return,
                };
                match run_scheduler_pack_task(
                    SchedulerPackTask::ExecPlan { seq },
                    &mut ctx.scratch,
                    &shared,
                ) {
                    Ok(output) => {
                        *output_slots[seq]
                            .lock()
                            .expect("scheduler pack output slot poisoned") = Some(output);
                    }
                    Err(err) => {
                        store_scheduler_error(first_error.as_ref(), abort_flag.as_ref(), err)
                    }
                }
            }
        },
    );

    let tasks: Vec<SchedulerPackTask> = (0..plan_count)
        .map(|seq| SchedulerPackTask::ExecPlan { seq })
        .collect();
    ex.spawn_external_batch(tasks)
        .map_err(|_| scheduler_queue_rejected_error(false))?;
    ex.join();

    if let Some(err) = take_scheduler_error(first_error.as_ref()) {
        return Err(err);
    }

    collect_plan_outputs(shared.plans.as_slice(), output_slots.as_ref())
}

struct ShardDispatchPlan {
    shard_meta: Vec<SchedulerShardMeta>,
    tasks: Vec<SchedulerPackTask>,
}

fn build_shard_dispatch_plan(
    plans: &[PackPlan],
    shard_counts: &[(u16, usize)],
) -> ShardDispatchPlan {
    let mut shard_meta = Vec::with_capacity(plans.len());
    let mut tasks = Vec::new();

    for (plan_idx, plan) in plans.iter().enumerate() {
        let exec_plan = build_scheduler_shard_exec_plan(plan);
        let plan_hot_deps = PackPlanHotDeps::from_plan(plan);
        let exec_len = exec_plan.len();
        if exec_len == 0 {
            shard_meta.push(SchedulerShardMeta {
                exec_plan,
                plan_hot_deps,
                candidate_ranges: Vec::new(),
                shard_ranges: Vec::new(),
            });
            continue;
        }

        let candidate_ranges = if matches!(&exec_plan, SchedulerShardExecPlan::Explicit(_)) {
            let mut ranges = Vec::new();
            build_candidate_ranges(plan, &mut ranges);
            ranges
        } else {
            Vec::new()
        };
        let shard_count = shard_count_for_pack(shard_counts, plan.pack_id);
        let shard_ranges = shard_ranges(exec_len, shard_count);
        for shard_idx in 0..shard_ranges.len() {
            tasks.push(SchedulerPackTask::ExecShard {
                plan_idx,
                shard_idx,
            });
        }

        shard_meta.push(SchedulerShardMeta {
            exec_plan,
            plan_hot_deps,
            candidate_ranges,
            shard_ranges,
        });
    }

    ShardDispatchPlan { shard_meta, tasks }
}

fn build_shard_slot_bases(shard_meta: &[SchedulerShardMeta]) -> Vec<usize> {
    let mut shard_slot_base = Vec::with_capacity(shard_meta.len());
    let mut total_shard_slots = 0usize;
    for meta in shard_meta {
        shard_slot_base.push(total_shard_slots);
        total_shard_slots += meta.shard_ranges.len();
    }
    shard_slot_base
}

fn merge_shard_outputs(
    plans: &[PackPlan],
    shard_meta: &[SchedulerShardMeta],
    shard_slots: &[Mutex<Option<SchedulerPackExecOutput>>],
    shard_slot_base: &[usize],
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    let mut merged = Vec::with_capacity(plans.len());
    for plan_idx in 0..plans.len() {
        let base = shard_slot_base[plan_idx];
        let shard_count = shard_meta[plan_idx].shard_ranges.len();
        if shard_count == 0 {
            merged.push(empty_scheduler_output());
            continue;
        }

        let mut reports = Vec::with_capacity(shard_count);
        let mut scanned_shards = Vec::with_capacity(shard_count);
        let mut skipped = Vec::new();
        let mut common_metrics = GitScanCommonMetrics::default();
        for shard_idx in 0..shard_count {
            let shard_output = shard_slots[base + shard_idx]
                .lock()
                .expect("scheduler shard output slot poisoned")
                .take()
                .ok_or({
                    GitScanError::PackExec(PackExecError::SchedulerShardOutputMissing {
                        plan_idx,
                        shard_idx,
                    })
                })?;
            reports.push(shard_output.report);
            scanned_shards.push(shard_output.scanned);
            common_metrics.merge_from(&shard_output.common_metrics);
        }

        let report = if reports.len() == 1 {
            reports.pop().expect("len checked")
        } else {
            merge_pack_exec_reports(reports)
        };
        collect_skipped_candidates(&plans[plan_idx], &report.skips, &mut skipped);
        let scanned = merge_scanned_blobs(scanned_shards);
        merged.push(SchedulerPackExecOutput {
            report,
            scanned,
            skipped,
            common_metrics,
        });
    }
    Ok(merged)
}

fn execute_sharded_tasks(
    env: SchedulerExecEnv,
    plans: Arc<Vec<PackPlan>>,
    shard_counts: Vec<(u16, usize)>,
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    let plan_count = plans.len();
    let ShardDispatchPlan { shard_meta, tasks } =
        build_shard_dispatch_plan(plans.as_ref(), &shard_counts);

    if tasks.is_empty() {
        return Ok((0..plan_count).map(|_| empty_scheduler_output()).collect());
    }

    let shard_slot_base = Arc::new(build_shard_slot_bases(&shard_meta));
    let total_shard_slots = shard_meta
        .iter()
        .map(|meta| meta.shard_ranges.len())
        .sum::<usize>();
    type ShardSlot = Mutex<Option<SchedulerPackExecOutput>>;
    let shard_slots: Arc<Vec<ShardSlot>> =
        Arc::new((0..total_shard_slots).map(|_| Mutex::new(None)).collect());
    let shared = env.build_shared(plans, Some(Arc::new(shard_meta)));
    let first_error: Arc<Mutex<Option<GitScanError>>> = Arc::new(Mutex::new(None));
    let abort_flag = Arc::new(AtomicBool::new(false));

    let pack_cache_bytes = env.pack_cache_bytes;
    let ex = Executor::<SchedulerPackTask>::new(
        env.executor_config(),
        move |_wid| scheduler_worker_scratch(pack_cache_bytes),
        {
            let shared = Arc::clone(&shared);
            let shard_slots = Arc::clone(&shard_slots);
            let shard_slot_base = Arc::clone(&shard_slot_base);
            let first_error = Arc::clone(&first_error);
            let abort_flag = Arc::clone(&abort_flag);
            move |task, ctx: &mut WorkerCtx<SchedulerPackTask, SchedulerPackScratch>| {
                if abort_flag.load(Ordering::Acquire) {
                    return;
                }
                let (plan_idx, shard_idx) = match task {
                    SchedulerPackTask::ExecShard {
                        plan_idx,
                        shard_idx,
                    } => (plan_idx, shard_idx),
                    SchedulerPackTask::ExecPlan { .. } => return,
                };
                match run_scheduler_pack_task(
                    SchedulerPackTask::ExecShard {
                        plan_idx,
                        shard_idx,
                    },
                    &mut ctx.scratch,
                    &shared,
                ) {
                    Ok(output) => {
                        let flat_idx = shard_slot_base[plan_idx] + shard_idx;
                        *shard_slots[flat_idx]
                            .lock()
                            .expect("scheduler shard output slot poisoned") = Some(output);
                    }
                    Err(err) => {
                        store_scheduler_error(first_error.as_ref(), abort_flag.as_ref(), err)
                    }
                }
            }
        },
    );

    ex.spawn_external_batch(tasks)
        .map_err(|_| scheduler_queue_rejected_error(true))?;
    ex.join();

    if let Some(err) = take_scheduler_error(first_error.as_ref()) {
        return Err(err);
    }

    let shard_meta = shared.shard_meta.as_ref().ok_or(GitScanError::PackExec(
        PackExecError::SchedulerShardMetadataUnavailable,
    ))?;
    merge_shard_outputs(
        shared.plans.as_slice(),
        shard_meta.as_slice(),
        shard_slots.as_ref(),
        shard_slot_base.as_ref(),
    )
}

/// Input bundle for scheduler execution setup.
///
/// Grouping these fields keeps strategy selection and environment assembly
/// in one focused context object instead of threading many discrete args
/// through helper internals.
struct SchedulerExecRequest {
    engine: Arc<Engine>,
    event_sink: Arc<dyn EventSink>,
    midx_bytes: BytesView,
    object_format: ObjectFormat,
    pack_paths: Arc<Vec<PathBuf>>,
    loose_dirs: Arc<Vec<PathBuf>>,
    pack_mmaps: Arc<Vec<Option<Mmap>>>,
    path_arena: Arc<ByteArena>,
    spill_dir: Arc<PathBuf>,
    plans: Vec<PackPlan>,
    pack_decode: PackDecodeLimits,
    pack_io: PackIoLimits,
    adapter_cfg: EngineAdapterConfig,
    pack_cache_bytes: u32,
    workers: usize,
    pin_threads: bool,
    commit_graph: Arc<super::commit_graph::CommitGraphIndex>,
    commit_meta_seen: Arc<gossip_stdx::AtomicBitSet>,
}

fn execute_pack_plans_with_scheduler_request(
    request: SchedulerExecRequest,
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    let SchedulerExecRequest {
        engine,
        event_sink,
        midx_bytes,
        object_format,
        pack_paths,
        loose_dirs,
        pack_mmaps,
        path_arena,
        spill_dir,
        plans,
        pack_decode,
        pack_io,
        adapter_cfg,
        pack_cache_bytes,
        workers,
        pin_threads,
        commit_graph,
        commit_meta_seen,
    } = request;
    if plans.is_empty() {
        return Ok(Vec::new());
    }

    let workers = workers.max(1);
    let strategy = select_pack_exec_strategy(workers, &plans);
    let exec_workers = match strategy {
        PackExecStrategy::Serial => 1,
        PackExecStrategy::PackParallel | PackExecStrategy::IntraPackSharded { .. } => workers,
    };

    let env = SchedulerExecEnv {
        engine,
        event_sink,
        midx_bytes,
        object_format,
        pack_paths,
        loose_dirs,
        pack_mmaps,
        path_arena,
        spill_dir,
        pack_decode,
        pack_io,
        adapter_cfg,
        pack_cache_bytes,
        exec_workers,
        pin_threads,
        commit_graph,
        commit_meta_seen,
    };

    let plans = Arc::new(plans);
    match strategy {
        PackExecStrategy::Serial | PackExecStrategy::PackParallel => execute_plan_tasks(env, plans),
        PackExecStrategy::IntraPackSharded { shard_counts } => {
            execute_sharded_tasks(env, plans, shard_counts)
        }
    }
}

type ExecutePackPlansWithSchedulerFn = fn(
    Arc<Engine>,
    Arc<dyn EventSink>,
    BytesView,
    ObjectFormat,
    Arc<Vec<PathBuf>>,
    Arc<Vec<PathBuf>>,
    Arc<Vec<Option<Mmap>>>,
    Arc<ByteArena>,
    Arc<PathBuf>,
    Vec<PackPlan>,
    PackDecodeLimits,
    PackIoLimits,
    EngineAdapterConfig,
    u32,
    usize,
    bool,
    Arc<super::commit_graph::CommitGraphIndex>,
    Arc<gossip_stdx::AtomicBitSet>,
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError>;

/// Compatibility call boundary used by `runner_odb_blob` and
/// `runner_diff_history`.
///
/// Scheduler setup is documented and implemented in
/// `execute_pack_plans_with_scheduler_request`; this symbol forwards inputs
/// into that request object while preserving the existing callable name.
pub(super) static EXECUTE_PACK_PLANS_WITH_SCHEDULER: ExecutePackPlansWithSchedulerFn =
    |engine,
     event_sink,
     midx_bytes,
     object_format,
     pack_paths,
     loose_dirs,
     pack_mmaps,
     path_arena,
     spill_dir,
     plans,
     pack_decode,
     pack_io,
     adapter_cfg,
     pack_cache_bytes,
     workers,
     pin_threads,
     commit_graph,
     commit_meta_seen| {
        execute_pack_plans_with_scheduler_request(SchedulerExecRequest {
            engine,
            event_sink,
            midx_bytes,
            object_format,
            pack_paths,
            loose_dirs,
            pack_mmaps,
            path_arena,
            spill_dir,
            plans,
            pack_decode,
            pack_io,
            adapter_cfg,
            pack_cache_bytes,
            workers,
            pin_threads,
            commit_graph,
            commit_meta_seen,
        })
    };

pub(super) use EXECUTE_PACK_PLANS_WITH_SCHEDULER as execute_pack_plans_with_scheduler;

/// Load loose candidate objects and scan their blob payloads.
///
/// For each candidate the loose object is decoded via `pack_io`. Blobs are
/// forwarded to `adapter.emit_loose`; non-blobs, missing objects, and decode
/// failures are recorded in `skipped` so the run can complete with partial
/// results.
///
/// # Errors
///
/// Returns `GitScanError::PackIo` only for unexpected I/O errors (e.g. a
/// permission failure on the objects directory). Recoverable per-object
/// problems are captured in `skipped` instead.
pub(super) fn scan_loose_candidates(
    candidates: &[LooseCandidate],
    paths: &ByteArena,
    adapter: &mut EngineAdapter,
    pack_io: &mut PackIo<'_>,
    skipped: &mut Vec<SkippedCandidate>,
) -> Result<(), GitScanError> {
    for candidate in candidates {
        let path = paths.get(candidate.ctx.path_ref);
        match pack_io.load_loose_object(&candidate.oid) {
            Ok(Some((ObjectKind::Blob, bytes))) => {
                adapter.emit_loose(candidate, path, &bytes)?;
            }
            Ok(Some((_kind, _bytes))) => {
                skipped.push(SkippedCandidate {
                    oid: candidate.oid,
                    reason: CandidateSkipReason::LooseNotBlob,
                });
            }
            Ok(None) => {
                skipped.push(SkippedCandidate {
                    oid: candidate.oid,
                    reason: CandidateSkipReason::LooseMissing,
                });
            }
            Err(PackIoError::LooseObject { .. }) => {
                skipped.push(SkippedCandidate {
                    oid: candidate.oid,
                    reason: CandidateSkipReason::LooseDecode,
                });
            }
            Err(err) => return Err(GitScanError::PackIo(err)),
        }
    }
    Ok(())
}

/// Map pack-level skip records back to candidate-level skip entries.
///
/// [`SkipRecord`]s carry raw pack offsets; this function binary-searches
/// `plan.candidate_offsets` (which are sorted by offset) to find every
/// candidate at each skipped offset. Multiple candidates can share an
/// offset (e.g. identical blobs referenced by different paths), and each
/// one produces a separate [`SkippedCandidate`] entry in `out`.
///
/// Complexity: O(S × log N) where S = `skips.len()` and N =
/// `candidate_offsets.len()` (two `partition_point` calls per skip).
pub(super) fn collect_skipped_candidates(
    plan: &PackPlan,
    skips: &[SkipRecord],
    out: &mut Vec<SkippedCandidate>,
) {
    if skips.is_empty() {
        return;
    }
    let offsets = &plan.candidate_offsets;
    for skip in skips {
        let reason = CandidateSkipReason::from_pack_skip(&skip.reason);
        // Two partition_points carve out the equal-range [start..end) of
        // candidates at this offset (sorted invariant of candidate_offsets).
        let start = offsets.partition_point(|c| c.offset < skip.offset);
        let end = offsets.partition_point(|c| c.offset <= skip.offset);
        for cand in &offsets[start..end] {
            let idx = cand.cand_idx as usize;
            if let Some(entry) = plan.candidates.get(idx) {
                out.push(SkippedCandidate {
                    oid: entry.oid,
                    reason,
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmark support
// ---------------------------------------------------------------------------

#[cfg(feature = "bench")]
mod bench_support {
    use super::*;
    use crate::object_id::OidBytes;
    use crate::pack_candidates::PackCandidate;
    use crate::pack_plan_model::{BaseLoc, DeltaDep, DeltaKind, PackPlanStats, NONE_U32};

    /// Build a synthetic `PackPlan` for benchmarking strategy selection.
    ///
    /// Creates a plan with `need_count` evenly-spaced offsets spanning
    /// `span_bytes`, plus `forward_deps` forward delta dependencies and
    /// `external_deps` external (OID-based) dependencies.
    pub fn bench_synthetic_plan(
        pack_id: u16,
        need_count: usize,
        span_bytes: u64,
        forward_deps: usize,
        external_deps: usize,
    ) -> PackPlan {
        let effective_span = span_bytes.max(need_count.saturating_sub(1) as u64);
        let step = if need_count <= 1 {
            0
        } else {
            (effective_span / (need_count as u64 - 1)).max(1)
        };
        let need_offsets: Vec<u64> = (0..need_count)
            .map(|idx| (idx as u64).saturating_mul(step))
            .collect();

        let mut delta_deps = Vec::with_capacity(forward_deps.saturating_add(external_deps));
        for idx in 0..forward_deps {
            let offset = idx as u64;
            delta_deps.push(DeltaDep {
                offset,
                kind: DeltaKind::Ofs,
                base: BaseLoc::Offset(offset.saturating_add(1)),
                data_start: 0,
                delta_size: 0,
            });
        }
        for idx in 0..external_deps {
            let offset = forward_deps.saturating_add(idx) as u64;
            delta_deps.push(DeltaDep {
                offset,
                kind: DeltaKind::Ref,
                base: BaseLoc::External {
                    oid: OidBytes::default(),
                },
                data_start: 0,
                delta_size: 0,
            });
        }
        delta_deps.sort_by_key(|dep| dep.offset);
        let mut delta_dep_index = vec![NONE_U32; need_count];
        for (dep_idx, dep) in delta_deps.iter().enumerate() {
            if let Ok(need_idx) = need_offsets.binary_search(&dep.offset) {
                delta_dep_index[need_idx] = dep_idx as u32;
            }
        }

        PackPlan {
            pack_id,
            oid_len: 20,
            max_delta_depth: 64,
            candidates: Vec::<PackCandidate>::new(),
            candidate_offsets: Vec::new(),
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats::empty(),
        }
    }

    /// Build a synthetic `PackPlan` with regular backward offset deps for
    /// benchmarking locality estimation.
    ///
    /// Creates a plan with `need_count` offsets where every offset at index
    /// `i >= dep_gap` depends on the offset at `i - dep_gap`.
    pub fn bench_synthetic_locality_plan(need_count: usize, dep_gap: usize) -> PackPlan {
        let span_bytes = need_count.saturating_mul(1024) as u64;
        let mut plan = bench_synthetic_plan(0, need_count, span_bytes, 0, 0);
        if dep_gap == 0 || dep_gap >= need_count {
            return plan;
        }

        let mut delta_deps = Vec::with_capacity(need_count.saturating_sub(dep_gap));
        for dep_need_idx in dep_gap..need_count {
            delta_deps.push(DeltaDep {
                offset: plan.need_offsets[dep_need_idx],
                kind: DeltaKind::Ofs,
                base: BaseLoc::Offset(plan.need_offsets[dep_need_idx - dep_gap]),
                data_start: 0,
                delta_size: 0,
            });
        }
        let mut delta_dep_index = vec![NONE_U32; need_count];
        for (dep_idx, dep) in delta_deps.iter().enumerate() {
            if let Ok(need_idx) = plan.need_offsets.binary_search(&dep.offset) {
                delta_dep_index[need_idx] = dep_idx as u32;
            }
        }

        plan.delta_deps = delta_deps;
        plan.delta_dep_index = delta_dep_index;
        plan
    }

    /// Apply locality shard cap using the current (new) code path.
    ///
    /// This is the production code: `build_exec_pos_by_need` is hoisted
    /// outside the loop so the `Vec<usize>` is allocated once and reused
    /// across all iterations.
    pub fn bench_apply_locality_shard_cap(plan: &PackPlan, cap: usize) -> usize {
        apply_locality_shard_cap(plan, cap)
    }

    /// Select pack execution strategy using the current (new) code path.
    ///
    /// Returns a discriminant tag (0 = Serial, 1 = PackParallel, 2 = Sharded)
    /// because `PackExecStrategy` is `pub(super)`. The benchmark only measures
    /// computation cost; the tag prevents dead-code elimination.
    pub fn bench_select_strategy(workers: usize, plans: &[PackPlan]) -> u8 {
        match select_pack_exec_strategy(workers, plans) {
            PackExecStrategy::Serial => 0,
            PackExecStrategy::PackParallel => 1,
            PackExecStrategy::IntraPackSharded { .. } => 2,
        }
    }
}

#[cfg(feature = "bench")]
pub use bench_support::{
    bench_apply_locality_shard_cap, bench_select_strategy, bench_synthetic_locality_plan,
    bench_synthetic_plan,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "runner_exec_tests.rs"]
mod tests;

// ============================================================================
// Kani Bounded Model Checking Proofs
// ============================================================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Proves that `shard_id_for_exec_position` produces a valid,
    /// complete, and balanced partitioning for all bounded inputs.
    ///
    /// For symbolic `len ∈ [1..16]` and `shards ∈ [1..len]`:
    /// 1. All positions `0..len` map to a valid shard id `< shards`.
    /// 2. Every shard id `0..shards` is assigned to at least one position.
    /// 3. Shard sizes differ by at most 1 (balanced partitioning invariant).
    #[kani::proof]
    #[kani::unwind(18)]
    fn shard_id_partitions_cover_all_positions() {
        let len: usize = kani::any();
        let shards: usize = kani::any();
        kani::assume(len >= 1 && len <= 16);
        kani::assume(shards >= 1 && shards <= len);

        let mut counts = vec![0usize; shards];
        for pos in 0..len {
            let shard = shard_id_for_exec_position(pos, len, shards);
            kani::assert(shard < shards, "shard id must be < shards");
            counts[shard] += 1;
        }

        // Every shard must be assigned at least one position.
        for s in 0..shards {
            kani::assert(counts[s] > 0, "every shard must have at least one position");
        }

        // Balanced: max shard size - min shard size <= 1.
        let mut min_count = len;
        let mut max_count = 0;
        for s in 0..shards {
            if counts[s] < min_count {
                min_count = counts[s];
            }
            if counts[s] > max_count {
                max_count = counts[s];
            }
        }
        kani::assert(
            max_count - min_count <= 1,
            "shard sizes must differ by at most 1",
        );
    }
}
