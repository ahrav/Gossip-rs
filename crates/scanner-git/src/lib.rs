//! Git scanning pipeline modules.
//!
//! The `repo_open` module produces `RepoJobState`: it resolves repo paths,
//! detects object format, and loads the start set plus watermarks needed for
//! incremental Git scanning. Artifacts (MIDX, commit-graph) are always built
//! in memory by `artifact_acquire`.
//!
//! Pipeline overview:
//! 1. `repo_open` resolves repo paths, detects object format, and loads start set state.
//! 2. `commit_walk` builds the commit plan.
//! 3. `tree_diff` extracts candidate blobs and paths.
//! 4. `spiller` dedupes and filters candidates against the seen store.
//! 5. `mapping_bridge` maps unique blobs to pack/loose candidates.
//! 6. `pack_plan` builds per-pack decode plans from pack candidates.
//! 7. `pack_exec` decodes blobs and streams bytes into `engine_adapter`.
//! 8. `finalize` builds persistence ops, and `persist` commits them atomically.
//!
//! # Output model
//! - Metadata phases emit stable plans and candidate lists without reading blobs.
//! - Execution phases decode blobs with explicit limits and report per-offset
//!   skips with deterministic ordering guarantees for staged outputs.
//! - Finalization emits write ops for data and (on complete runs) watermarks.
//!
//! # Feature gates
//! - `rocksdb` enables the RocksDB persistence adapter.
//! - `git-perf` enables performance counters for pack decode and scan stages.
//!
//! # Invariants
//! - Metadata stages (repo open through pack planning) do not read blob payloads.
//! - Pack execution and engine adaptation read and scan blob bytes with explicit limits.
//! - File reads are bounded by explicit limits.
//! - `seen_blob`/`finding` persistence keys are deterministic for identical repo
//!   state and configuration.
//! - In ODB-blob mode with parallel introduction, blob attribution context
//!   (`commit_id`, path, flags) is not guaranteed deterministic.
//!
//! # Facade Contract
//! This module is the public stage-oriented facade for git scanning. Re-exports
//! are grouped by pipeline stage so callers can depend on stable boundaries
//! (repo open/artifact acquisition, commit loading, tree diff/candidate
//! extraction, spill/dedup/mapping, pack planning/execution, engine scanning,
//! and finalize/persist) instead of individual internal modules.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_macros)]
// Targeted clippy overrides for patterns used intentionally in this crate.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::type_complexity)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]

macro_rules! perf_set {
    ($target:expr, $field:ident, $val:expr) => {
        #[cfg(feature = "git-perf")]
        {
            $target.$field = $val;
        }
    };
}
pub(crate) use perf_set;

macro_rules! perf_let {
    ($name:ident = $val:expr) => {
        #[cfg(feature = "git-perf")]
        let $name = $val;
    };
    (mut $name:ident = $val:expr) => {
        #[cfg(feature = "git-perf")]
        let mut $name = $val;
    };
}
pub(crate) use perf_let;

pub mod alloc_guard;
pub mod artifact_acquire;
pub mod blob_introducer;
pub mod blob_spill;
pub mod byte_arena;
pub mod bytes;
pub(crate) mod cache_common;
pub mod commit_graph;
pub mod commit_graph_mem;
pub mod commit_loader;
pub mod commit_parse;
pub mod commit_walk;
pub mod commit_walk_limits;
#[cfg(test)]
pub(crate) mod delta_test_helpers;
pub mod engine_adapter;
pub mod errors;
pub mod events;
pub mod finalize;
pub mod identity_intern;
pub mod identity_parse;
pub mod json_write;
pub mod limits;
pub mod mapping_bridge;
pub mod midx;
pub mod midx_build;
pub mod midx_error;
#[cfg(test)]
pub(crate) mod midx_test_builder;
pub mod object_id;
pub mod object_store;
pub mod oid_index;
pub mod pack_cache;
pub mod pack_candidates;
pub mod pack_decode;
pub mod pack_delta;
pub mod pack_exec;
pub mod pack_idx;
pub mod pack_inflate;
pub mod pack_io;
pub mod pack_plan;
pub mod pack_plan_model;
pub mod pack_reader;
pub mod path_policy;
mod perf_stats;
pub mod persist;
pub mod persist_rocksdb;
pub mod policy_hash;
pub mod preflight;
pub mod preflight_error;
pub mod preflight_limits;
pub mod repo;
pub mod repo_open;
pub(crate) mod repo_paths;
pub mod run_format;
pub mod run_reader;
pub mod run_writer;
pub mod runner;
pub mod runner_diff_history;
pub mod runner_exec;
pub mod runner_odb_blob;
pub mod seen_store;
pub mod snapshot_plan;
pub mod spill_arena;
pub mod spill_chunk;
pub mod spill_limits;
pub mod spill_merge;
pub mod spiller;
pub mod start_set;
#[cfg(test)]
pub mod test_utils;
pub mod tree_cache;
pub mod tree_candidate;
pub mod tree_delta_cache;
pub mod tree_diff;
pub mod tree_diff_limits;
pub mod tree_entry;
pub mod tree_order;
pub mod tree_stream;
pub mod unique_blob;
pub mod watermark_keys;
pub mod work_items;

pub use alloc_guard::{enabled as alloc_guard_enabled, set_enabled as set_alloc_guard_enabled};
// ── Stage 1: Repo open & artifact acquisition ──────────────────────────
pub use artifact_acquire::{
    acquire_commit_graph, acquire_commit_graph_with_identities, acquire_midx, ArtifactAcquireError,
    ArtifactBuildLimits, MidxAcquireResult,
};
pub use limits::RepoOpenLimits;
pub use midx::MidxView;
pub use midx_build::{build_midx_bytes, MidxBuildError, MidxBuildLimits};
pub use object_id::{ObjectFormat, OidBytes};
pub use preflight::{
    preflight, ArtifactPaths, ArtifactStatus, PreflightMaintenance, PreflightReport,
};
pub use preflight_error::PreflightError;
pub use preflight_limits::PreflightLimits;
pub use repo::{GitRepoPaths, RepoKind};
pub use repo_open::{
    repo_open, RefWatermarkStore, RepoArtifactFingerprint, RepoArtifactMmaps, RepoArtifactPaths,
    RepoJobState, StartSetRef, StartSetResolver,
};
pub use start_set::{StartSetConfig, StartSetId};

// ── Stage 2: Commit loading & graph construction ────────────────────────
pub use commit_graph::CommitGraphIndex;
pub use commit_graph_mem::CommitGraphMem;
pub use commit_loader::{
    load_commits_from_tips, load_commits_with_identities, load_shallow_boundary_roots,
    resolve_pack_paths_from_midx, CommitLoadError, CommitLoadLimits, LoadedCommit,
};
pub use commit_parse::{parse_commit, CommitParseError, CommitParseLimits, ParsedCommit};
pub use commit_walk::{
    introduced_by_plan, topo_order_positions, CommitGraph, CommitPlanIter, ParentScratch,
    PlannedCommit,
};
pub use commit_walk_limits::CommitWalkLimits;
pub use identity_intern::{CommitIdentityIds, IdentityInterner, SENTINEL_ID};
pub use repo_paths::{collect_loose_dirs, collect_pack_dirs};

// ── Stage 3: Tree diff & candidate extraction ───────────────────────────
pub use blob_introducer::{BlobIntroStats, BlobIntroducer, SeenSets};
pub use object_store::{ObjectStore, TreeBytes, TreeSource};
pub use path_policy::PathClass;
pub use tree_candidate::{
    CandidateBuffer, CandidateContext, CandidateSink, ChangeKind, ResolvedCandidate, TreeCandidate,
};
pub use tree_diff::{TreeDiffStats, TreeDiffWalker};
pub use tree_diff_limits::TreeDiffLimits;
pub use tree_entry::{EntryKind, TreeEntry, TreeEntryIter};
pub use tree_order::{git_tree_file_name_cmp, git_tree_name_cmp};
pub use unique_blob::{CollectedUniqueBlob, CollectingUniqueBlobSink, UniqueBlob, UniqueBlobSink};

// ── Stage 4: Spill, dedup & mapping ─────────────────────────────────────
pub use mapping_bridge::{MappingBridge, MappingBridgeConfig, MappingStats};
pub use oid_index::OidIndex;
pub use seen_store::{AlwaysSeenStore, InMemorySeenStore, NeverSeenStore, SeenBlobStore};
pub use spill_chunk::CandidateChunk;
pub use spill_limits::SpillLimits;
pub use spill_merge::{merge_all, RunMerger};
pub use spiller::{SpillStats, Spiller};

// ── Stage 5: Pack planning & execution ──────────────────────────────────
pub use pack_cache::{CachedObject, PackCache};
pub use pack_candidates::{
    CappedPackCandidateSink, CollectingPackCandidateSink, LooseCandidate, PackCandidate,
    PackCandidateSink,
};
pub use pack_decode::{entry_header_at, inflate_entry_payload, PackDecodeError, PackDecodeLimits};
pub use pack_delta::{apply_delta, DeltaError};
pub use pack_exec::{
    aggregate_cache_reject_histogram, build_candidate_ranges, execute_pack_plan,
    execute_pack_plan_with_reader, execute_pack_plan_with_scratch_indices, merge_pack_exec_reports,
    CacheRejectHistogram, ExternalBase, ExternalBaseProvider, PackExecError, PackExecReport,
    PackExecStats, PackObjectSink, SkipReason, SkipRecord, CACHE_REJECT_BUCKETS,
};
pub use pack_idx::{IdxError, IdxOidIter, IdxView};
pub use pack_io::{PackIo, PackIoError, PackIoLimits};
#[doc(hidden)]
pub use pack_plan::{build_exec_order, ExecOrderResult};
pub use pack_plan::{build_pack_plans, OidResolver, PackPlanConfig, PackPlanError, PackView};
pub use pack_plan_model::{
    BaseLoc, CandidateAtOffset, DeltaDep, DeltaKind, PackPlan, PackPlanStats,
};
pub use pack_reader::{PackReadError, PackReader, SlicePackReader};

// ── Stage 6: Engine scanning ────────────────────────────────────────────
pub use engine_adapter::{
    scan_blob_chunked, EngineAdapter, EngineAdapterConfig, EngineAdapterError, FindingKey,
    FindingSpan, GitScanCommonMetrics, ScannedBlob, ScannedBlobs, ScoredFinding,
    DEFAULT_CHUNK_BYTES,
};
pub use events::{
    CommitMetaEvent, EventSink, GitEvent, GitEventOutput, IdentityDictionaryEvent, NullEventSink,
    ScanEvent, VecEventSink,
};

// ── Stage 7: Finalize & persist ─────────────────────────────────────────
pub use finalize::{
    build_finalize_ops, FinalizeInput, FinalizeOutcome, FinalizeOutput, FinalizeStats, RefEntry,
    WriteOp,
};
pub use persist::{persist_finalize_output, InMemoryPersistenceStore, PersistenceStore};
pub use snapshot_plan::snapshot_plan;
pub use watermark_keys::{
    decode_ref_watermark_value, encode_ref_watermark_value, KeyArena, KeyRef, NS_REF_WATERMARK,
};

// ── Cross-cutting: errors, config, runner, I/O ──────────────────────────
pub use byte_arena::{ByteArena, ByteRef};
pub use bytes::BytesView;
pub use errors::PersistError;
pub use errors::{CommitPlanError, MappingCandidateKind, RepoOpenError, SpillError, TreeDiffError};
pub use policy_hash::{policy_hash, MergeDiffMode, PolicyHash};
pub use run_format::{RunContext, RunHeader, RunRecord};
pub use run_reader::RunReader;
pub use run_writer::RunWriter;
pub(crate) use runner::auto_pack_exec_workers_for_in_pack;
pub use runner::{
    run_git_scan, CandidateSkipReason, GitScanAllocStats, GitScanConfig, GitScanError, GitScanMode,
    GitScanReport, GitScanResult, GitScanStageNanos, PackMmapLimits, SkippedCandidate,
};
pub use scanner_engine::perf_counters::{
    reset as reset_git_perf, snapshot as git_perf_snapshot, GitPerfStats,
};
pub use scanner_engine::{
    demo_engine, demo_engine_with_anchor_mode,
    demo_engine_with_anchor_mode_and_max_transform_depth, demo_engine_with_anchor_mode_and_tuning,
    demo_tuning, AnchorMode, AnchorPolicy, Engine, FileId, Gate, NormHash, RuleSpec, ScanScratch,
    TransformConfig, TransformId, TransformMode, ValidatorKind,
};
pub use work_items::WorkItems;

// ── Benchmark support ───────────────────────────────────────────────────
#[cfg(feature = "bench")]
pub use runner_exec::{
    bench_apply_locality_shard_cap, bench_select_strategy, bench_synthetic_locality_plan,
    bench_synthetic_plan,
};
