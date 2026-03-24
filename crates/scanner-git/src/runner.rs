//! End-to-end Git scan runner — types, config, and thin dispatcher.
//!
//! This module defines the public types (`GitScanConfig`, `GitScanError`,
//! `GitScanReport`, etc.) and the [`run_git_scan`] entry point, which is a
//! thin dispatcher that delegates to mode-specific pipeline modules:
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`runner_odb_blob`](super::runner_odb_blob) | ODB-blob fast-path pipeline |
//! | [`runner_diff_history`](super::runner_diff_history) | Diff-history pipeline |
//! | [`runner_exec`](super::runner_exec) | Shared pack execution helpers |
//!
//! # Pipeline
//! 1. Open the repo (start set resolution, watermarks, artifact readiness check).
//! 2. Build MIDX and commit-graph in memory via `artifact_acquire`.
//! 3. Build commit plan (`introduced_by_plan`).
//! 4. Dispatch to mode-specific pipeline (ODB-blob or diff-history).
//! 5. Post-execution artifact stability check.
//! 6. Finalize, optionally persist, and return report.
//!
//! # Modes
//! - **Diff-history**: walk commits, diff trees, spill/dedupe candidates, then
//!   batch-plan and execute pack decode + scan.
//! - **ODB-blob fast**: compute the unique blob set from the commit graph,
//!   then scan in pack order with streaming plan generation; retries via
//!   spill/dedupe on candidate cap overflow.
//!
//! # Invariants
//! - MIDX completeness is verified before pack execution.
//! - Pack cache sizing must fit in `u32` (checked before execution).
//!
//! # Notes
//! - Loose objects are decoded via `PackIo::load_loose_object`; failures are
//!   recorded as skipped candidates.
//! - Persistence is optional; callers can run the pipeline without a store.

use std::io;
use std::path::{Path, PathBuf};
#[cfg(feature = "git-perf")]
use std::time::Instant;

use scanner_engine::Engine;
use scanner_scheduler::AllocStatsDelta;

use super::artifact_acquire::{
    acquire_commit_graph, acquire_commit_graph_with_identities, acquire_midx, ArtifactAcquireError,
    ArtifactBuildLimits,
};
use super::byte_arena::ByteArena;
use super::commit_graph::CommitGraphIndex;
use super::commit_walk::introduced_by_plan;
use super::commit_walk_limits::CommitWalkLimits;
use super::engine_adapter::{
    CommitMetaContext, EngineAdapterConfig, GitScanCommonMetrics, ScannedBlobs,
};
use super::errors::{CommitPlanError, PersistError, RepoOpenError, SpillError, TreeDiffError};
use super::finalize::{build_finalize_ops, FinalizeInput, FinalizeOutput};
use super::identity_intern::IdentityInterner;
use super::limits::RepoOpenLimits;
use super::mapping_bridge::{MappingBridgeConfig, MappingStats};
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::OidBytes;
use super::pack_decode::PackDecodeLimits;
use super::pack_exec::{PackExecError, PackExecReport, SkipReason};
use super::pack_io::{PackIoError, PackIoLimits};
use super::pack_plan::{PackPlanConfig, PackPlanError};
use super::pack_plan_model::PackPlanStats;
use super::persist::{persist_finalize_output, PersistenceStore};
use super::policy_hash::MergeDiffMode;
use super::repo_open::{repo_open, RefWatermarkStore, StartSetResolver};
use super::seen_store::SeenBlobStore;
use super::spill_limits::SpillLimits;
use super::spiller::SpillStats;
use super::start_set::StartSetConfig;
use super::tree_diff::TreeDiffStats;
use super::tree_diff_limits::TreeDiffLimits;

use super::runner_exec::build_ref_entries;
use crate::{perf_let, perf_set};

/// Limits for pack file mmapping during scan execution.
#[derive(Clone, Copy, Debug)]
pub struct PackMmapLimits {
    /// Maximum number of pack files to mmap.
    ///
    /// Counted from MIDX-resolved pack paths.
    pub max_open_packs: u16,
    /// Maximum total bytes to mmap across all packs.
    ///
    /// Computed from file sizes; this caps address space usage, not RSS.
    pub max_total_bytes: u64,
}

impl PackMmapLimits {
    /// Safe defaults suitable for large monorepos.
    pub const DEFAULT: Self = Self {
        max_open_packs: 128,
        max_total_bytes: 8 * 1024 * 1024 * 1024,
    };

    /// Restrictive limits for testing or constrained environments.
    pub const RESTRICTIVE: Self = Self {
        max_open_packs: 8,
        max_total_bytes: 512 * 1024 * 1024,
    };

    /// Validates that limits are internally consistent.
    ///
    /// # Panics
    ///
    /// Panics if limits are invalid (indicates a configuration bug).
    #[track_caller]
    pub const fn validate(&self) {
        assert!(self.max_open_packs > 0, "must allow at least 1 pack");
        assert!(self.max_total_bytes > 0, "pack mmap budget must be > 0");
    }
}

/// Git scan runner configuration.
///
/// The defaults mirror the Git scanning limits and are intended for
/// production usage. Callers should set `repo_id` and `policy_hash` to
/// stable identifiers for their environment to ensure consistent
/// persistence keys and scan identity.
///
/// `pack_cache_bytes` is an in-memory cache cap; oversized values are rejected
/// at runtime when converting to `u32`.
///
/// `spill_dir` controls where intermediate spill files are written. When
/// `None`, a unique temp directory is created per run.
#[derive(Clone, Debug)]
pub struct GitScanConfig {
    /// Scan mode selection (diff-history vs ODB-blob fast path).
    pub scan_mode: GitScanMode,
    /// Stable repository identifier used to namespace persisted keys.
    pub repo_id: u64,
    /// Stable policy hash that identifies the scan configuration.
    pub policy_hash: [u8; 32],
    /// Start set selection (default branch, explicit refs, etc.).
    pub start_set: StartSetConfig,
    /// Merge diff strategy for merge commits.
    pub merge_diff_mode: MergeDiffMode,
    /// Repo-open limits (mmap sizes, ref caps, etc.).
    pub repo_open: RepoOpenLimits,
    /// Commit-walk limits (parents, batching).
    pub commit_walk: CommitWalkLimits,
    /// Tree-diff limits (depth, byte budgets, candidate caps).
    pub tree_diff: TreeDiffLimits,
    /// Spill/dedupe limits (chunk sizes, run caps, seen batching).
    pub spill: SpillLimits,
    /// Mapping bridge limits (arena sizes, candidate caps).
    pub mapping: MappingBridgeConfig,
    /// Pack planning configuration (cluster sizing, delta bounds).
    pub pack_plan: PackPlanConfig,
    /// Pack decode limits (inflate and object size caps).
    pub pack_decode: PackDecodeLimits,
    /// Pack IO limits (loose object caps, base resolution).
    pub pack_io: PackIoLimits,
    /// Engine adapter configuration (chunk sizes and overlap).
    pub engine_adapter: EngineAdapterConfig,
    /// Pack mmap limits during pack execution (count + total bytes).
    pub pack_mmap: PackMmapLimits,
    /// Pack cache size in bytes (must fit in `u32`).
    pub pack_cache_bytes: usize,
    /// Total pack-exec worker threads.
    ///
    /// Controls the number of parallel workers for pack decode + scan
    /// execution. Each worker handles I/O (page faults) and compute
    /// (decode + scan). The scheduler selects Serial (1 worker) or
    /// PackParallel/IntraPackSharded (this many workers) based on
    /// plan structure.
    ///
    /// Default: detected hardware parallelism (1× cores). CLI orchestration
    /// may scale this using repository-size heuristics via
    /// `auto_pack_exec_workers_for_in_pack`.
    ///
    /// Total pack threads in the system ≤ scheduler_workers × pack_exec_workers.
    pub pack_exec_workers: usize,

    /// Number of threads for parallel blob introduction (Stage 1).
    ///
    /// Workers share an `AtomicSeenSets` bitmap for deduplication and each
    /// get their own `ObjectStore`, tree cache, and candidate collector.
    /// Cache budgets are divided by this count to keep total memory constant.
    /// In parallel mode, blob attribution context (`commit_id`, path, flags)
    /// is race-winner based and not deterministic across worker counts.
    ///
    /// Set to 1 to disable parallel blob intro (serial path).
    /// Capped at 8 because inflate is memory-bandwidth-bound and shows
    /// diminishing returns beyond that.
    ///
    /// Default: min(available_parallelism, 8), clamped to at least 1.
    pub blob_intro_workers: usize,
    /// Pin worker threads to CPU cores (Linux only, no-op elsewhere).
    pub pin_threads: bool,
    /// Optional spill directory override. When `None`, a unique temp directory is used.
    pub spill_dir: Option<PathBuf>,
    /// Limits for in-memory artifact construction.
    ///
    /// Applied when disk artifacts are missing and `run_git_scan` builds
    /// MIDX and commit-graph in memory.
    pub artifact_build: ArtifactBuildLimits,
    /// When true, extract author/committer identity data and emit
    /// identity_dictionary + enriched commit_meta events.
    /// Default: false. Zero overhead when disabled.
    pub enrich_identities: bool,
}

impl Default for GitScanConfig {
    fn default() -> Self {
        let pack_decode = PackDecodeLimits::new(64, 8 * 1024 * 1024, 8 * 1024 * 1024);
        Self {
            // Default to ODB-blob for throughput; diff-history must be explicit.
            scan_mode: GitScanMode::OdbBlobFast,
            repo_id: 1,
            policy_hash: [0u8; 32],
            start_set: StartSetConfig::DefaultBranchOnly,
            merge_diff_mode: MergeDiffMode::AllParents,
            repo_open: RepoOpenLimits::DEFAULT,
            commit_walk: CommitWalkLimits::DEFAULT,
            tree_diff: TreeDiffLimits::DEFAULT,
            spill: SpillLimits::DEFAULT,
            mapping: MappingBridgeConfig::default(),
            pack_plan: PackPlanConfig::default(),
            pack_decode,
            pack_io: PackIoLimits::new(pack_decode, PackPlanConfig::default().max_delta_depth),
            engine_adapter: EngineAdapterConfig::default(),
            pack_mmap: PackMmapLimits::DEFAULT,
            pack_cache_bytes: 64 * 1024 * 1024,
            pack_exec_workers: default_pack_exec_workers(),
            blob_intro_workers: default_blob_intro_workers(),
            pin_threads: scanner_scheduler::affinity::default_pin_threads(),
            spill_dir: None,
            artifact_build: ArtifactBuildLimits::default(),
            enrich_identities: false,
        }
    }
}

/// Baseline pack-exec worker budget.
///
/// Uses detected hardware parallelism (1× cores). CLI orchestration may
/// scale this baseline using repository-size heuristics.
fn default_pack_exec_workers() -> usize {
    detected_parallelism()
}

/// Returns detected hardware parallelism, falling back to 1.
#[inline(always)]
fn detected_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .max(1)
}

/// Maximum pack execution workers regardless of core count.
///
/// Prevents excessive memory usage from per-worker `Decompress` (~37 KiB),
/// scratch buffers, and `PackCache` allocations (4 MB floor each).
/// On a 64-core machine with the 6x large-repo multiplier the uncapped
/// count would be 384, consuming over 1.5 GiB in cache alone.
pub(crate) const MAX_PACK_EXEC_WORKERS: usize = 128;

/// Repositories below this `in-pack` object count use the baseline 1× core
/// multiplier for pack execution.
///
/// Boundary is exclusive (`< SMALL`).
pub(crate) const PACK_EXEC_SMALL_REPO_MAX_IN_PACK_OBJECTS: u64 = 100_000;
/// Repositories below this `in-pack` object count (and above small) use the
/// medium 3× core multiplier for pack execution.
///
/// Boundary is exclusive (`< MEDIUM`), so values `>= MEDIUM` use the large tier.
pub(crate) const PACK_EXEC_MEDIUM_REPO_MAX_IN_PACK_OBJECTS: u64 = 2_000_000;

/// Compute the pack-exec worker multiplier from repository `in-pack` size.
///
/// Tier ranges:
/// - `[0, SMALL)` -> `1`
/// - `[SMALL, MEDIUM)` -> `3`
/// - `[MEDIUM, +inf)` -> `6`
///
/// Larger repositories intentionally over-subscribe cores to better hide
/// pack I/O and page-fault latency during decode + scan.
#[inline(always)]
pub(crate) fn pack_exec_worker_multiplier_for_in_pack(in_pack_objects: u64) -> usize {
    if in_pack_objects < PACK_EXEC_SMALL_REPO_MAX_IN_PACK_OBJECTS {
        1
    } else if in_pack_objects < PACK_EXEC_MEDIUM_REPO_MAX_IN_PACK_OBJECTS {
        3
    } else {
        6
    }
}

/// Auto-size pack-exec workers from repository `in-pack` size and detected cores.
#[inline(always)]
pub fn auto_pack_exec_workers_for_in_pack(in_pack_objects: u64) -> usize {
    auto_pack_exec_workers_for_in_pack_with_cores(in_pack_objects, detected_parallelism())
}

/// Auto-size pack-exec workers from repository `in-pack` size and caller-provided cores.
///
/// `cores` is clamped to at least `1`, and multiplication is saturating to
/// prevent overflow if a caller passes an extreme core count in tests.
/// The result is capped at [`MAX_PACK_EXEC_WORKERS`] to prevent OOM on
/// high-core-count machines where per-worker memory (Decompress ~37 KiB,
/// scratch buffers, PackCache 4 MB floor) would otherwise be excessive.
#[inline(always)]
pub(crate) fn auto_pack_exec_workers_for_in_pack_with_cores(
    in_pack_objects: u64,
    cores: usize,
) -> usize {
    let multiplier = pack_exec_worker_multiplier_for_in_pack(in_pack_objects);
    cores
        .max(1)
        .saturating_mul(multiplier)
        .min(MAX_PACK_EXEC_WORKERS)
}

/// Blob-intro worker count.
///
/// Capped at 8 because inflate is memory-bandwidth-bound and shows
/// diminishing returns beyond that on typical hardware. Falls back to
/// 1 when `available_parallelism` is unavailable.
fn default_blob_intro_workers() -> usize {
    let parallelism = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    parallelism.clamp(1, 8)
}

/// Emits all identity dictionary entries before any `CommitMeta` events.
///
/// Ordering is significant: consumers can resolve identity IDs in subsequent
/// commit metadata only if this dictionary is emitted first. Entries are
/// emitted in intern ID order (`0..N`) as provided by [`IdentityInterner::iter`].
fn emit_identity_dictionary(sink: &dyn crate::events::EventSink, interner: &IdentityInterner) {
    use crate::events::{IdentityDictionaryEvent, ScanEvent};
    for (id, value) in interner.iter() {
        sink.emit(ScanEvent::IdentityDictionary(IdentityDictionaryEvent {
            id,
            value,
        }));
    }
}

/// Git scan execution mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GitScanMode {
    /// Current diff-history pipeline (tree diff + spill + mapping + pack plan).
    DiffHistory,
    /// ODB-blob fast path (unique-blob walk + pack-order scan).
    #[default]
    OdbBlobFast,
}

impl std::fmt::Display for GitScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DiffHistory => write!(f, "diff-history"),
            Self::OdbBlobFast => write!(f, "odb-blob"),
        }
    }
}

/// Result of a Git scan run.
///
/// Wraps `GitScanReport` as a newtype so callers destructure explicitly.
/// The report contains stage timings, finding counts, skip records, and
/// the finalize output (including watermark operations).
#[derive(Debug)]
pub struct GitScanResult(pub GitScanReport);

/// Reason a candidate blob was skipped during the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSkipReason {
    /// Loose object was missing on disk.
    LooseMissing,
    /// Loose object failed to decode.
    LooseDecode,
    /// Loose object was not a blob.
    LooseNotBlob,
    /// Pack entry was not a blob.
    PackNotBlob,
    /// Pack entry failed to decode.
    PackDecode,
    /// Delta application failed.
    PackDelta,
    /// Delta base offset was missing from the cache.
    PackBaseMissing,
    /// External base OID could not be resolved.
    PackExternalBaseMissing,
    /// External base provider failed.
    PackExternalBaseError,
    /// Pack parse error surfaced as a skip.
    PackParse,
}

impl CandidateSkipReason {
    /// Converts a pack-execution [`SkipReason`] into the public skip taxonomy.
    ///
    /// Lossy: the inner error payload is discarded. Callers that need the
    /// original error should retain the `SkipReason` separately.
    pub(super) fn from_pack_skip(reason: &SkipReason) -> Self {
        match reason {
            SkipReason::PackParse(_) => Self::PackParse,
            SkipReason::Decode(_) => Self::PackDecode,
            SkipReason::Delta(_) => Self::PackDelta,
            SkipReason::BaseMissing { .. } => Self::PackBaseMissing,
            SkipReason::ExternalBaseMissing { .. } => Self::PackExternalBaseMissing,
            SkipReason::ExternalBaseError { .. } => Self::PackExternalBaseError,
            SkipReason::NotBlob => Self::PackNotBlob,
        }
    }

    /// Returns a stable label for reporting.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LooseMissing => "loose_missing",
            Self::LooseDecode => "loose_decode",
            Self::LooseNotBlob => "loose_not_blob",
            Self::PackNotBlob => "pack_not_blob",
            Self::PackDecode => "pack_decode",
            Self::PackDelta => "pack_delta",
            Self::PackBaseMissing => "pack_base_missing",
            Self::PackExternalBaseMissing => "pack_external_base_missing",
            Self::PackExternalBaseError => "pack_external_base_error",
            Self::PackParse => "pack_parse",
        }
    }
}

/// Candidate blob skipped during the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkippedCandidate {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Why the candidate was skipped.
    pub reason: CandidateSkipReason,
}

/// Per-stage nanoseconds for the git scan pipeline.
///
/// All fields are only populated when the `git-perf` feature is enabled.
/// Most are wall-clock durations; `mapping` and `scan` come from
/// thread-local perf counters (accumulated across pack-exec workers).
///
/// Shape is stable across feature flags. In non-`git-perf` builds, all fields
/// remain available and default to zero.
#[derive(Debug, Clone, Copy, Default)]
pub struct GitScanStageNanos {
    /// Tree diff stage time.
    pub tree_diff: u64,
    /// Commit-plan construction time.
    pub commit_plan: u64,
    /// First-introduced blob walk time (ODB-blob mode).
    pub blob_intro: u64,
    /// Spill/dedupe stage time.
    pub spill: u64,
    /// Pack candidate collection time (ODB-blob mode).
    pub pack_collect: u64,
    /// Mapping bridge time.
    pub mapping: u64,
    /// Pack planning stage time.
    pub pack_plan: u64,
    /// Pack execution stage time.
    pub pack_exec: u64,
    /// Loose object scan time (ODB-blob mode).
    pub loose_scan: u64,
    /// Scan time.
    pub scan: u64,
}

/// Allocation deltas captured across hot stages.
///
/// Shape is stable across feature flags. In non-`git-perf` builds, fields
/// remain available and default to zero.
#[derive(Debug, Clone, Copy, Default)]
pub struct GitScanAllocStats {
    /// Allocation deltas for pack decode + scan.
    pub pack_exec: AllocStatsDelta,
}

/// Summary report for a completed scan.
///
/// Contains per-stage statistics, pack execution reports, skipped candidates,
/// and finalize output. Use [`format_metrics`](Self::format_metrics) for
/// machine-parseable output.
#[derive(Debug)]
pub struct GitScanReport {
    /// Number of commits processed in the plan.
    pub commit_count: usize,
    /// Tree diff stage statistics.
    pub tree_diff_stats: TreeDiffStats,
    /// Spill/dedupe stage statistics.
    pub spill_stats: SpillStats,
    /// Pack mapping statistics.
    pub mapping_stats: MappingStats,
    /// Per-pack-plan statistics.
    pub pack_plan_stats: Vec<PackPlanStats>,
    /// Pack plan configuration used for this run.
    pub pack_plan_config: PackPlanConfig,
    /// Total delta dependency count across pack plans.
    pub pack_plan_delta_deps_total: u64,
    /// Maximum delta dependency count in a single pack plan.
    pub pack_plan_delta_deps_max: u32,
    /// Pack decode + scan reports, in the same order as `pack_plan_stats`.
    pub pack_exec_reports: Vec<PackExecReport>,
    /// Candidates skipped with explicit reasons.
    pub skipped_candidates: Vec<SkippedCandidate>,
    /// Finalize output and persistence stats.
    pub finalize: FinalizeOutput,
    /// Always-on counters used by CLI summary output.
    pub common_metrics: GitScanCommonMetrics,
    /// Stage timing data (nanoseconds).
    pub stage_nanos: GitScanStageNanos,
    /// Git perf counter snapshot (pack decode, scan, mapping).
    pub perf_stats: scanner_engine::perf_counters::GitPerfStats,
    /// Allocation deltas for hot stages.
    pub alloc_stats: GitScanAllocStats,
    /// Actual computed per-worker pack cache budget (bytes).
    pub pack_cache_per_worker_bytes: usize,
}

impl GitScanReport {
    /// Formats metrics as machine-parseable `key=value\n` lines.
    ///
    /// The key set is stable across feature flags. In non-`git-perf` builds,
    /// perf-derived values remain present and are emitted as zero.
    #[must_use]
    pub fn format_metrics(&self) -> String {
        fn bytes_per_sec(bytes: u64, nanos: u64) -> u64 {
            if bytes == 0 || nanos == 0 {
                0
            } else {
                bytes.saturating_mul(1_000_000_000).saturating_div(nanos)
            }
        }

        fn nanos_per_byte(bytes: u64, nanos: u64) -> u64 {
            if bytes == 0 {
                0
            } else {
                nanos.saturating_div(bytes)
            }
        }

        fn push_line<T: std::fmt::Display>(out: &mut String, key: &str, value: T) {
            out.push_str(key);
            out.push('=');
            out.push_str(&value.to_string());
            out.push('\n');
        }

        let stages = &self.stage_nanos;
        let perf = &self.perf_stats;
        let tree_diff_bytes = self.tree_diff_stats.tree_bytes_loaded;
        let mut out = String::new();

        push_line(&mut out, "stage.tree_diff.nanos", stages.tree_diff);
        push_line(&mut out, "stage.commit_plan.nanos", stages.commit_plan);
        push_line(&mut out, "stage.blob_intro.nanos", stages.blob_intro);
        push_line(&mut out, "stage.spill.nanos", stages.spill);
        push_line(&mut out, "stage.pack_collect.nanos", stages.pack_collect);
        push_line(&mut out, "stage.mapping.nanos", stages.mapping);
        push_line(&mut out, "stage.pack_plan.nanos", stages.pack_plan);
        push_line(&mut out, "stage.pack_exec.nanos", stages.pack_exec);
        push_line(&mut out, "stage.loose_scan.nanos", stages.loose_scan);
        push_line(&mut out, "stage.scan.nanos", stages.scan);

        push_line(&mut out, "tree_diff.bytes", tree_diff_bytes);
        push_line(
            &mut out,
            "tree_diff.bytes_per_sec",
            bytes_per_sec(tree_diff_bytes, stages.tree_diff),
        );
        push_line(
            &mut out,
            "tree_diff.ns_per_byte",
            nanos_per_byte(tree_diff_bytes, stages.tree_diff),
        );

        push_line(&mut out, "tree_load.calls", perf.tree_load_calls);
        push_line(&mut out, "tree_load.bytes", perf.tree_load_bytes);
        push_line(&mut out, "tree_load.nanos", perf.tree_load_nanos);
        push_line(
            &mut out,
            "tree_load.bytes_per_sec",
            bytes_per_sec(perf.tree_load_bytes, perf.tree_load_nanos),
        );
        push_line(
            &mut out,
            "tree_load.ns_per_byte",
            nanos_per_byte(perf.tree_load_bytes, perf.tree_load_nanos),
        );
        push_line(&mut out, "tree_cache.hits", perf.tree_cache_hits);
        push_line(
            &mut out,
            "tree_delta_cache.hits",
            perf.tree_delta_cache_hits,
        );
        push_line(
            &mut out,
            "tree_delta_cache.misses",
            perf.tree_delta_cache_misses,
        );
        push_line(
            &mut out,
            "tree_delta_cache.bytes",
            perf.tree_delta_cache_bytes,
        );
        push_line(
            &mut out,
            "tree_delta_cache.hit_nanos",
            perf.tree_delta_cache_hit_nanos,
        );
        push_line(
            &mut out,
            "tree_delta_cache.miss_nanos",
            perf.tree_delta_cache_miss_nanos,
        );
        push_line(&mut out, "tree_delta_chain.0", perf.tree_delta_chain_0);
        push_line(&mut out, "tree_delta_chain.1", perf.tree_delta_chain_1);
        push_line(&mut out, "tree_delta_chain.2_3", perf.tree_delta_chain_2_3);
        push_line(&mut out, "tree_delta_chain.4_7", perf.tree_delta_chain_4_7);
        push_line(
            &mut out,
            "tree_delta_chain.8_plus",
            perf.tree_delta_chain_8_plus,
        );
        push_line(&mut out, "tree_spill.hits", perf.tree_spill_hits);
        push_line(&mut out, "tree_object.loads", perf.tree_object_loads);
        push_line(&mut out, "tree_object.bytes", perf.tree_object_bytes);
        push_line(&mut out, "tree_object.nanos", perf.tree_object_nanos);
        push_line(
            &mut out,
            "tree_object.bytes_per_sec",
            bytes_per_sec(perf.tree_object_bytes, perf.tree_object_nanos),
        );
        push_line(
            &mut out,
            "tree_object.ns_per_byte",
            nanos_per_byte(perf.tree_object_bytes, perf.tree_object_nanos),
        );
        push_line(&mut out, "tree_object.pack", perf.tree_object_pack);
        push_line(&mut out, "tree_object.loose", perf.tree_object_loose);
        push_line(&mut out, "tree_inflate.bytes", perf.tree_inflate_bytes);
        push_line(&mut out, "tree_inflate.nanos", perf.tree_inflate_nanos);
        push_line(
            &mut out,
            "tree_inflate.bytes_per_sec",
            bytes_per_sec(perf.tree_inflate_bytes, perf.tree_inflate_nanos),
        );
        push_line(
            &mut out,
            "tree_inflate.ns_per_byte",
            nanos_per_byte(perf.tree_inflate_bytes, perf.tree_inflate_nanos),
        );
        push_line(
            &mut out,
            "tree_delta_apply.bytes",
            perf.tree_delta_apply_bytes,
        );
        push_line(
            &mut out,
            "tree_delta_apply.nanos",
            perf.tree_delta_apply_nanos,
        );
        push_line(
            &mut out,
            "tree_delta_apply.bytes_per_sec",
            bytes_per_sec(perf.tree_delta_apply_bytes, perf.tree_delta_apply_nanos),
        );
        push_line(
            &mut out,
            "tree_delta_apply.ns_per_byte",
            nanos_per_byte(perf.tree_delta_apply_bytes, perf.tree_delta_apply_nanos),
        );

        push_line(&mut out, "pack_inflate.bytes", perf.pack_inflate_bytes);
        push_line(&mut out, "pack_inflate.nanos", perf.pack_inflate_nanos);
        push_line(
            &mut out,
            "pack_inflate.bytes_per_sec",
            bytes_per_sec(perf.pack_inflate_bytes, perf.pack_inflate_nanos),
        );
        push_line(
            &mut out,
            "pack_inflate.ns_per_byte",
            nanos_per_byte(perf.pack_inflate_bytes, perf.pack_inflate_nanos),
        );

        push_line(&mut out, "delta_apply.bytes", perf.delta_apply_bytes);
        push_line(&mut out, "delta_apply.nanos", perf.delta_apply_nanos);
        push_line(
            &mut out,
            "delta_apply.bytes_per_sec",
            bytes_per_sec(perf.delta_apply_bytes, perf.delta_apply_nanos),
        );
        push_line(
            &mut out,
            "delta_apply.ns_per_byte",
            nanos_per_byte(perf.delta_apply_bytes, perf.delta_apply_nanos),
        );

        push_line(&mut out, "scan.bytes", perf.scan_bytes);
        push_line(&mut out, "scan.nanos", perf.scan_nanos);
        push_line(
            &mut out,
            "scan.bytes_per_sec",
            bytes_per_sec(perf.scan_bytes, perf.scan_nanos),
        );
        push_line(
            &mut out,
            "scan.ns_per_byte",
            nanos_per_byte(perf.scan_bytes, perf.scan_nanos),
        );

        push_line(&mut out, "mapping.calls", perf.mapping_calls);
        push_line(&mut out, "mapping.nanos", perf.mapping_nanos);
        push_line(
            &mut out,
            "mapping.ns_per_call",
            nanos_per_byte(perf.mapping_calls.max(1), perf.mapping_nanos),
        );

        push_line(&mut out, "spill.runs", self.spill_stats.spill_runs);
        push_line(&mut out, "spill.bytes", self.spill_stats.spill_bytes);

        push_line(
            &mut out,
            "alloc.pack_exec.allocs",
            self.alloc_stats.pack_exec.allocs,
        );
        push_line(
            &mut out,
            "alloc.pack_exec.bytes",
            self.alloc_stats.pack_exec.bytes_allocated,
        );
        push_line(
            &mut out,
            "alloc.pack_exec.reallocs",
            self.alloc_stats.pack_exec.reallocs,
        );
        push_line(
            &mut out,
            "alloc.pack_exec.deallocs",
            self.alloc_stats.pack_exec.deallocs,
        );

        out
    }
}

/// Common output from a scan mode pipeline.
///
/// Both ODB-blob and diff-history modes produce this struct. The dispatcher
/// uses it to build the final `GitScanReport` after finalize and persist.
///
/// This is a post-hoc gather: assembled after all execution completes and
/// destructured once during finalize. If execution becomes incremental,
/// consider splitting into a hot accumulator (scanned, skips, reports) and
/// cold stats (everything else) for cache locality.
pub(super) struct ScanModeOutput {
    // -- Hot during finalize: touched when building FinalizeInput. --
    /// Scanned blob results and finding arena.
    pub scanned: ScannedBlobs,
    /// Path arena used for candidate path storage.
    pub path_arena: ByteArena,
    /// Candidates skipped with explicit reasons.
    pub skipped_candidates: Vec<SkippedCandidate>,

    // -- Execution reports: forwarded verbatim into GitScanReport. --
    /// Pack decode + scan reports, one per pack plan.
    pub pack_exec_reports: Vec<PackExecReport>,
    /// Per-pack-plan statistics.
    pub pack_plan_stats: Vec<PackPlanStats>,
    /// Pack plan configuration used for this run.
    pub pack_plan_config: PackPlanConfig,
    /// Total delta dependency count across pack plans.
    pub pack_plan_delta_deps_total: u64,
    /// Maximum delta dependency count in a single pack plan.
    pub pack_plan_delta_deps_max: u32,

    // -- Cold stats: read once when assembling the report. --
    /// Tree diff stage statistics.
    pub tree_diff_stats: TreeDiffStats,
    /// Spill/dedupe stage statistics.
    pub spill_stats: SpillStats,
    /// Pack mapping statistics.
    pub mapping_stats: MappingStats,
    /// Always-on counters used by CLI summary output.
    pub common_metrics: GitScanCommonMetrics,
    /// Stage timing data (nanoseconds).
    pub stage_nanos: GitScanStageNanos,
    /// Allocation deltas for hot stages.
    pub alloc_stats: GitScanAllocStats,
    /// Actual computed per-worker pack cache budget (bytes).
    pub pack_cache_per_worker_bytes: usize,
}

/// Git scan error taxonomy.
///
/// Errors are organized by pipeline stage. Early stages (repo open, commit
/// plan) fail fast; later stages (pack exec, persist) may produce partial
/// output before failing. `ConcurrentMaintenance` is a special sentinel
/// that triggers retry logic in callers.
///
/// All variants implement `Display` and `Error`. The `source()` chain
/// preserves the inner error for diagnostic logging.
#[derive(Debug, thiserror::Error)]
pub enum GitScanError {
    /// Repo open phase failed (bad metadata, missing refs, etc.).
    #[error("{0}")]
    RepoOpen(#[from] RepoOpenError),
    /// Commit plan construction failed (e.g. missing commit-graph entries).
    #[error("{0}")]
    CommitPlan(#[from] CommitPlanError),
    /// Tree diff walker encountered an error (corrupt trees, depth exceeded).
    #[error("{0}")]
    TreeDiff(#[from] TreeDiffError),
    /// Spill/dedupe pipeline error (I/O failure on spill files).
    #[error("{0}")]
    Spill(#[from] SpillError),
    /// MIDX parsing or validation error (corrupt header, missing packs).
    #[error("{0}")]
    Midx(#[from] MidxError),
    /// Pack plan construction error (out-of-range pack IDs, corrupt headers).
    #[error("{0}")]
    PackPlan(#[from] PackPlanError),
    /// Fatal pack execution error (decode failure that aborted a plan).
    #[error("{0}")]
    PackExec(#[from] PackExecError),
    /// Pack I/O error during loose object or cross-pack base resolution.
    #[error("{0}")]
    PackIo(#[from] PackIoError),
    /// Persistence store write failed.
    #[error("{0}")]
    Persist(#[from] PersistError),
    /// Underlying I/O error not covered by a more specific variant.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// Resource limit exceeded (pack mmap counts or cumulative bytes).
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
    /// Scan mode not yet implemented.
    #[error("scan mode not implemented: {0}")]
    UnsupportedMode(GitScanMode),
    /// In-memory artifact construction failed (MIDX or commit-graph build).
    #[error("artifact acquisition failed: {0}")]
    ArtifactAcquire(#[from] ArtifactAcquireError),
    /// Pack files or indices changed during the scan — a concurrent `git gc`
    /// or `git repack` invalidated the planned offsets. Callers should retry.
    #[error("concurrent git maintenance detected; artifacts changed during scan")]
    ConcurrentMaintenance,
}

/// Runs a full Git scan with the provided configuration and stores.
///
/// When disk artifacts (MIDX, commit-graph) are missing, this function
/// builds them in memory via `artifact_acquire`. On success, the scan is
/// finalized and optionally persisted.
///
/// # Inputs
/// - `repo_root` must reference a Git repository with readable metadata.
/// - `resolver` controls how the start set is chosen (default branch, refs, etc.).
/// - `seen_store` is used to dedupe candidates across runs.
/// - `watermark_store` supplies existing ref watermarks; it is not mutated here.
/// - `persist_store` is optional; when `Some`, finalize output (including
///   watermarks on complete runs) is committed atomically.
///
/// If no persistence store is provided, the caller is responsible for
/// interpreting `FinalizeOutcome` and storing watermarks as needed.
///
/// # Returns
/// A `GitScanResult` containing the `GitScanReport` when the scan finishes.
///
/// # Errors
/// Returns `ConcurrentMaintenance` if artifacts changed during the scan,
/// indicating another process modified the repository.
/// Pack mmap limits and cache sizing may surface as `GitScanError::ResourceLimit`.
/// Missing or corrupt maintenance artifacts (commit-graph, MIDX) surface as
/// `GitScanError::CommitPlan` or `GitScanError::Midx`.
///
/// # Artifact stability checks
///
/// Artifact stability is validated twice:
/// 1. Immediately after MIDX acquisition (before expensive traversal).
/// 2. After mode execution, before finalize/persist.
///
/// This avoids persisting results derived from pack offsets that changed
/// while the scan was in flight (for example due to concurrent `git gc`).
///
/// # Commit-meta emission
///
/// A [`CommitGraphIndex`] and shared [`AtomicBitSet`] are constructed from
/// the commit graph before mode dispatch. Both are passed (via `Arc`) to
/// every `EngineAdapter` created during pack execution and loose scanning,
/// enabling exactly-once `CommitMeta` event emission per referenced commit
/// across all worker threads.
///
/// # Determinism
/// Pack plans are built in pack order, and parallel execution reassembles
/// results by pack (and shard) order before finalize. This keeps persisted
/// scan output stable even when multiple workers are used.
///
/// Structured event ordering is intentionally non-deterministic under parallel
/// workers: `commit_meta` and `finding` events may interleave across commits,
/// and a finding may appear before its matching commit metadata.
///
/// # Caveats
/// - Loose object decode failures are recorded as skipped candidates and may
///   yield a `FinalizeOutcome::Partial`, suppressing watermark writes.
#[allow(clippy::too_many_arguments)]
pub fn run_git_scan(
    repo_root: &Path,
    engine: std::sync::Arc<Engine>,
    resolver: &dyn StartSetResolver,
    seen_store: &dyn SeenBlobStore,
    watermark_store: &dyn RefWatermarkStore,
    persist_store: Option<&dyn PersistenceStore>,
    config: &GitScanConfig,
    event_sink: std::sync::Arc<dyn crate::events::EventSink>,
) -> Result<GitScanResult, GitScanError> {
    scanner_engine::perf_counters::reset();

    let start_set_id = config.start_set.id();
    let mut repo = repo_open(
        repo_root,
        config.repo_id,
        config.policy_hash,
        start_set_id,
        resolver,
        watermark_store,
        config.repo_open,
    )?;

    let midx_result = acquire_midx(&mut repo, &config.artifact_build)?;
    // Fail fast if maintenance races with in-memory artifact build.
    if !repo.artifacts_unchanged()? {
        return Err(GitScanError::ConcurrentMaintenance);
    }
    let midx_view = MidxView::parse(midx_result.bytes.as_slice(), repo.object_format)?;
    // Conditional identity enrichment.
    let (cg, identity_interner) = if config.enrich_identities {
        let (cg_enriched, interner) = acquire_commit_graph_with_identities(
            &repo,
            &midx_view,
            &midx_result.pack_paths,
            &config.artifact_build,
        )?;
        (cg_enriched, Some(std::sync::Arc::new(interner)))
    } else {
        let cg = acquire_commit_graph(
            &repo,
            &midx_view,
            &midx_result.pack_paths,
            &config.artifact_build,
        )?;
        (cg, None)
    };

    // Commit plan (shared across both modes).
    perf_let!(plan_start = Instant::now());
    let plan = introduced_by_plan(&repo, &cg, config.commit_walk)?;
    perf_let!(commit_plan_nanos = plan_start.elapsed().as_nanos() as u64);

    // Build commit-graph index and emit-once bitset (shared by both modes).
    let cg_index = std::sync::Arc::new(CommitGraphIndex::build_from_mem(&cg)?);
    let commit_meta_seen =
        std::sync::Arc::new(gossip_stdx::AtomicBitSet::empty(cg_index.len().max(1)));

    // Emit identity dictionary before any CommitMeta events.
    if let Some(ref interner) = identity_interner {
        emit_identity_dictionary(&*event_sink, interner);
    }

    // Dispatch to mode-specific pipeline.
    let mk_commit_meta = || CommitMetaContext {
        event_sink: std::sync::Arc::clone(&event_sink),
        commit_graph_index: std::sync::Arc::clone(&cg_index),
        commit_meta_seen: std::sync::Arc::clone(&commit_meta_seen),
        identity_interner: identity_interner.clone(),
    };
    #[allow(unused_mut)]
    let mut output = match config.scan_mode {
        GitScanMode::OdbBlobFast => super::runner_odb_blob::run_odb_blob(
            &repo,
            std::sync::Arc::clone(&engine),
            seen_store,
            &cg_index,
            &plan,
            config,
            mk_commit_meta(),
        )?,
        GitScanMode::DiffHistory => super::runner_diff_history::run_diff_history(
            &repo,
            std::sync::Arc::clone(&engine),
            seen_store,
            &cg,
            &plan,
            config,
            mk_commit_meta(),
        )?,
    };
    perf_set!(output.stage_nanos, commit_plan, commit_plan_nanos);

    // Post-execution artifact stability check.
    if !repo.artifacts_unchanged()? {
        return Err(GitScanError::ConcurrentMaintenance);
    }

    // Finalize + persist.
    let refs = build_ref_entries(&repo);
    // Finalize uses only candidate OIDs for watermark/progress semantics;
    // reason taxonomy remains in the report payload.
    let skipped_candidate_oids = output
        .skipped_candidates
        .iter()
        .map(|entry| entry.oid)
        .collect();
    let finalize = build_finalize_ops(FinalizeInput {
        repo_id: config.repo_id,
        policy_hash: config.policy_hash,
        start_set_id,
        refs,
        scanned_blobs: output.scanned.blobs,
        finding_arena: &output.scanned.finding_arena,
        skipped_candidate_oids,
        path_arena: &output.path_arena,
    });

    if let Some(store) = persist_store {
        persist_finalize_output(store, &finalize)?;
    }

    // Perf snapshot: mapping and scan timings live in thread-local perf
    // counters (accumulated across pack-exec workers), not wall-clock
    // `Instant` measurements. We patch them into `stage_nanos` here so
    // they appear alongside the wall-clock stages in the final report.
    let perf_stats = scanner_engine::perf_counters::snapshot();
    perf_set!(output.stage_nanos, mapping, perf_stats.mapping_nanos);
    perf_set!(output.stage_nanos, scan, perf_stats.scan_nanos);

    Ok(GitScanResult(GitScanReport {
        commit_count: plan.len(),
        tree_diff_stats: output.tree_diff_stats,
        spill_stats: output.spill_stats,
        mapping_stats: output.mapping_stats,
        pack_plan_stats: output.pack_plan_stats,
        pack_plan_config: output.pack_plan_config,
        pack_plan_delta_deps_total: output.pack_plan_delta_deps_total,
        pack_plan_delta_deps_max: output.pack_plan_delta_deps_max,
        pack_exec_reports: output.pack_exec_reports,
        skipped_candidates: output.skipped_candidates,
        finalize,
        common_metrics: output.common_metrics,
        stage_nanos: output.stage_nanos,
        perf_stats,
        alloc_stats: output.alloc_stats,
        pack_cache_per_worker_bytes: output.pack_cache_per_worker_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scan_mode_matches_config_default() {
        assert_eq!(GitScanConfig::default().scan_mode, GitScanMode::default());
    }

    #[test]
    fn auto_pack_exec_workers_uses_in_pack_tiers() {
        assert_eq!(auto_pack_exec_workers_for_in_pack_with_cores(0, 12), 12);
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_SMALL_REPO_MAX_IN_PACK_OBJECTS - 1,
                12
            ),
            12
        );
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_SMALL_REPO_MAX_IN_PACK_OBJECTS,
                12
            ),
            36
        );
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_MEDIUM_REPO_MAX_IN_PACK_OBJECTS - 1,
                12
            ),
            36
        );
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_MEDIUM_REPO_MAX_IN_PACK_OBJECTS,
                12
            ),
            72
        );
    }

    #[test]
    fn auto_pack_exec_workers_clamps_cores_to_one() {
        assert_eq!(auto_pack_exec_workers_for_in_pack_with_cores(0, 0), 1);
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_SMALL_REPO_MAX_IN_PACK_OBJECTS,
                0
            ),
            3
        );
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_MEDIUM_REPO_MAX_IN_PACK_OBJECTS,
                0
            ),
            6
        );
    }

    #[test]
    fn auto_pack_exec_workers_caps_at_max_on_high_core_count() {
        // 64 cores × 6x multiplier = 384, but must be capped at MAX_PACK_EXEC_WORKERS (128).
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_MEDIUM_REPO_MAX_IN_PACK_OBJECTS,
                64
            ),
            MAX_PACK_EXEC_WORKERS
        );
    }

    #[test]
    fn auto_pack_exec_workers_below_cap_unchanged() {
        // 4 cores × 6x = 24, below cap — should remain 24.
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_MEDIUM_REPO_MAX_IN_PACK_OBJECTS,
                4
            ),
            24
        );
        // 16 cores × 6x = 96, below cap — should remain 96.
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_MEDIUM_REPO_MAX_IN_PACK_OBJECTS,
                16
            ),
            96
        );
    }

    #[test]
    fn auto_pack_exec_workers_boundary_at_cap() {
        // 22 cores × 6x = 132, exceeds cap — should be capped to 128.
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_MEDIUM_REPO_MAX_IN_PACK_OBJECTS,
                22
            ),
            MAX_PACK_EXEC_WORKERS
        );
        // 21 cores × 6x = 126, below cap — should remain 126.
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_MEDIUM_REPO_MAX_IN_PACK_OBJECTS,
                21
            ),
            126
        );
    }

    #[test]
    fn auto_pack_exec_workers_medium_tier_not_capped_below_max() {
        // 12 cores × 3x = 36, well below cap.
        assert_eq!(
            auto_pack_exec_workers_for_in_pack_with_cores(
                PACK_EXEC_SMALL_REPO_MAX_IN_PACK_OBJECTS,
                12
            ),
            36
        );
    }

    #[test]
    fn metrics_structs_expose_stable_fields() {
        let stage = GitScanStageNanos {
            tree_diff: 0,
            commit_plan: 0,
            blob_intro: 0,
            spill: 0,
            pack_collect: 0,
            mapping: 0,
            pack_plan: 0,
            pack_exec: 0,
            loose_scan: 0,
            scan: 0,
        };
        assert_eq!(stage.pack_exec, 0);

        let alloc = GitScanAllocStats {
            pack_exec: AllocStatsDelta::default(),
        };
        assert_eq!(alloc.pack_exec.allocs, 0);
    }

    #[test]
    fn format_metrics_emits_stable_key_set() {
        let report = GitScanReport {
            commit_count: 0,
            tree_diff_stats: TreeDiffStats::default(),
            spill_stats: SpillStats::default(),
            mapping_stats: MappingStats::default(),
            pack_plan_stats: Vec::new(),
            pack_plan_config: PackPlanConfig::default(),
            pack_plan_delta_deps_total: 0,
            pack_plan_delta_deps_max: 0,
            pack_exec_reports: Vec::new(),
            skipped_candidates: Vec::new(),
            finalize: FinalizeOutput {
                data_ops: Vec::new(),
                watermark_ops: Vec::new(),
                outcome: super::super::finalize::FinalizeOutcome::Complete,
                stats: super::super::finalize::FinalizeStats::default(),
            },
            common_metrics: GitScanCommonMetrics::default(),
            stage_nanos: GitScanStageNanos::default(),
            perf_stats: scanner_engine::perf_counters::GitPerfStats::default(),
            alloc_stats: GitScanAllocStats::default(),
            pack_cache_per_worker_bytes: 0,
        };

        let metrics = report.format_metrics();
        assert!(
            !metrics.is_empty(),
            "metrics output must not disappear when git-perf is disabled"
        );
        for key in [
            "stage.tree_diff.nanos",
            "tree_load.calls",
            "pack_inflate.bytes",
            "scan.nanos",
            "spill.runs",
            "alloc.pack_exec.allocs",
        ] {
            assert!(
                metrics.contains(&format!("{key}=0\n")),
                "expected stable key in metrics output: {key}"
            );
        }
    }
}
