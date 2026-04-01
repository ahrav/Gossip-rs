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
//! - `sim-harness` re-exports scheduler simulation modules to preserve
//!   scanner-rs-era harness import paths during DST migration.
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

/// Provides a debug-only allocation guard toggle for hot-path assertions.
pub mod alloc_guard;
/// Builds in-memory MIDX and commit-graph artifacts from pack index files.
pub mod artifact_acquire;
/// Implements blob introduction walk for ODB-blob scan mode.
pub mod blob_introducer;
/// Provides temporary spill files for oversized blob payloads.
pub mod blob_spill;
/// Provides an append-only byte arena for interning file paths.
pub mod byte_arena;
/// Defines a minimal read-only byte container for Git artifact data.
pub mod bytes;
pub(crate) mod cache_common;
/// Provides commit-graph indexing helpers for attribution-first ODB scans.
pub mod commit_graph;
/// Implements an in-memory commit graph built from loaded commit objects.
pub mod commit_graph_mem;
/// Implements BFS commit loading for in-memory commit graph construction.
pub mod commit_loader;
/// Provides a parser for Git commit objects (tree OID, parents, timestamp).
pub mod commit_parse;
/// Implements commit traversal and topological ordering for Git scanning.
pub mod commit_walk;
/// Defines hard caps and tunables for commit-graph traversal.
pub mod commit_walk_limits;
#[cfg(test)]
pub(crate) mod delta_test_helpers;
/// Bridges decoded blob bytes into the scan engine with overlap-safe chunking.
pub mod engine_adapter;
/// Defines stage-specific error types for Git scanning.
pub mod errors;
/// Defines the structured event surface for git scan output.
pub mod events;
/// Transforms scan results into stably ordered persistence write operations.
pub mod finalize;
/// Provides a deduplicating byte interner for identity strings.
pub mod identity_intern;
/// Implements zero-copy extraction of author/committer identity from commits.
pub mod identity_parse;
/// Provides JSON write helpers for git event sinks.
pub mod json_write;
/// Defines hard caps and tunables for repo discovery and open.
pub mod limits;
/// Maps unique blobs to pack/loose candidates via MIDX lookup.
pub mod mapping_bridge;
/// Implements a zero-copy multi-pack index (MIDX) parser.
pub mod midx;
/// Builds MIDX byte buffers in-memory using k-way merge of pack indexes.
pub mod midx_build;
/// Defines error types for multi-pack index parsing and lookup.
pub mod midx_error;
#[cfg(test)]
pub(crate) mod midx_test_builder;
pub mod native_ref_resolver;
/// Defines fixed-size, zero-heap object ID types for SHA-1 and SHA-256.
pub mod object_id;
/// Provides a pack/loose-backed object store for tree payload loading.
pub mod object_store;
/// Implements a fixed-capacity OID hash table for fast MIDX index lookups.
pub mod oid_index;
/// Implements a tiered set-associative cache for decoded pack objects.
pub mod pack_cache;
/// Defines pack and loose candidate output types for scan planning.
pub mod pack_candidates;
/// Provides pack decode primitives for bounded object inflation.
pub mod pack_decode;
/// Implements Git delta application with explicit output caps.
pub mod pack_delta;
/// Implements the pack plan executor with bounded decode and skip tracking.
pub mod pack_exec;
/// Implements a zero-copy parser for Git pack index (`.idx`) v2 files.
pub mod pack_idx;
/// Provides bounded inflate helpers and delta encoding for pack objects.
pub mod pack_inflate;
/// Provides pack I/O utilities for cross-pack REF delta base resolution.
pub mod pack_io;
/// Builds per-pack decode plans from candidate blobs and delta dependencies.
pub mod pack_plan;
/// Defines pack plan model types: candidates, delta deps, and execution order.
pub mod pack_plan_model;
/// Provides a pack byte reader abstraction for deterministic I/O.
pub mod pack_reader;
/// Implements a path policy classifier for tree diff candidates.
pub mod path_policy;
use gossip_stdx::perf_stats;
/// Defines the write-only persistence store contract and helpers.
pub mod persist;
/// Provides RocksDB-backed persistence adapters (feature-gated).
pub mod persist_rocksdb;
/// Implements a deterministic policy hash for scan configuration identity.
pub mod policy_hash;
/// Implements maintenance preflight checks for Git repository scanning.
pub mod preflight;
/// Defines error types for Git scanning preflight.
pub mod preflight_error;
/// Defines hard caps and tunables for Git maintenance preflight.
pub mod preflight_limits;
/// Implements repository path resolution and layout detection.
pub mod repo;
/// Normalizes local Git repo identities and derives stable repo namespaces.
pub mod repo_identity;
/// Implements repository discovery, open, and start set resolution.
pub mod repo_open;
pub(crate) mod repo_paths;
/// Defines the spill run file format and canonical record encoding.
pub mod run_format;
/// Implements a spill run reader with strict validation.
pub mod run_reader;
/// Implements a spill run writer for stable on-disk encoding.
pub mod run_writer;
/// Provides end-to-end Git scan runner types, config, and mode dispatcher.
pub mod runner;
/// Implements the diff-history scan pipeline with tree diff and spill stages.
pub mod runner_diff_history;
/// Provides shared pack execution helpers for both scan mode pipelines.
pub mod runner_exec;
/// Implements the ODB-blob fast-path scan pipeline.
pub mod runner_odb_blob;
/// Defines the seen-blob store interface for dedupe filtering.
pub mod seen_store;
/// Implements snapshot commit planning (scan tips without history walk).
pub mod snapshot_plan;
/// Provides an append-only, mmap-backed spill arena for tree payloads.
pub mod spill_arena;
/// Implements spill chunk storage with in-chunk dedupe and canonical ordering.
pub mod spill_chunk;
/// Defines hard caps and tunables for spill and dedupe operations.
pub mod spill_limits;
/// Implements k-way merge of sorted spill runs with duplicate removal.
pub mod spill_merge;
/// Provides shared spill-file naming helpers for sibling spill modules.
pub(crate) mod spill_path;
/// Implements the spill orchestrator for candidate collection and dedup.
pub mod spiller;
/// Defines start set configuration and deterministic identity hashing.
pub mod start_set;
#[cfg(test)]
pub mod test_utils;
#[cfg(feature = "sim-harness")]
pub use scanner_scheduler::sim;
#[cfg(feature = "sim-harness")]
pub use scanner_scheduler::sim_archive;
#[cfg(feature = "sim-harness")]
pub use scanner_scheduler::sim_scanner;
/// Provides a deterministic Git simulation harness for replayable testing.
#[cfg(feature = "sim-harness")]
pub mod sim_git_scan;
/// Implements a set-associative cache for tree object bytes.
pub mod tree_cache;
/// Defines candidate buffer types for tree diff output with interned paths.
pub mod tree_candidate;
/// Implements a set-associative cache for tree delta base bytes.
pub mod tree_delta_cache;
/// Implements the OID-only tree diff walker with explicit depth limits.
pub mod tree_diff;
/// Defines hard caps and tunables for tree diff and candidate collection.
pub mod tree_diff_limits;
/// Provides streaming zero-allocation Git tree entry parsing.
pub mod tree_entry;
/// Implements Git tree entry ordering (mode-aware name comparison).
pub mod tree_order;
/// Provides a streaming tree entry parser backed by a fixed-size buffer.
pub mod tree_stream;
/// Defines unique blob output types and dedup sink traits.
pub mod unique_blob;
/// Provides key building for watermark batch queries without per-key alloc.
pub mod watermark_keys;
/// Implements work item SoA tables with preallocated radix-sort scratch.
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
pub use native_ref_resolver::NativeRefResolver;
pub use object_id::{ObjectFormat, OidBytes};
pub use preflight::{
    preflight, ArtifactPaths, ArtifactStatus, PreflightMaintenance, PreflightReport,
};
pub use preflight_error::PreflightError;
pub use preflight_limits::PreflightLimits;
pub use repo::{GitRepoPaths, RepoKind};
pub use repo_identity::{
    derive_repo_id, normalize_local_repo_identities, NormalizedLocalRepoIdentity, RepoIdentityError,
};
pub use repo_open::{
    repo_open, RefWatermarkStore, RepoArtifactFingerprint, RepoArtifactMmaps, RepoArtifactPaths,
    RepoJobState, StartSetRef, StartSetResolver,
};
pub use repo_paths::{parse_hex_oid, HexOidParseError};
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
pub use runner::auto_pack_exec_workers_for_in_pack;
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
