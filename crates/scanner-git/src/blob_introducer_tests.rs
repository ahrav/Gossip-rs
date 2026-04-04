use super::{
    merge_worker_results, per_worker_loose_limit, BlobIntroStats, BlobIntroWorker, BlobIntroducer,
    SeenSets, WorkerResult,
};
use crate::byte_arena::{ByteArena, ByteRef};
use crate::commit_graph::CommitGraphIndex;
use crate::commit_walk::{CommitGraph, ParentScratch, PlannedCommit};
use crate::errors::{CommitPlanError, MappingCandidateKind, TreeDiffError};
use crate::midx::MidxView;
use crate::midx_test_builder::MidxBuilder;
use crate::object_id::{ObjectFormat, OidBytes};
use crate::object_store::TreeBytes;
use crate::oid_index::OidIndex;
use crate::pack_candidates::{LooseCandidate, PackCandidate};
use crate::tree_candidate::{CandidateBuffer, CandidateContext, ChangeKind};
use crate::tree_diff_limits::TreeDiffLimits;
use crate::TreeSource;
use gossip_stdx::atomic_seen_sets::AtomicSeenSets;

use gix_commitgraph::Position;
use std::sync::atomic::{AtomicBool, Ordering};

fn oid(byte: u8) -> OidBytes {
    OidBytes::sha1([byte; 20])
}

fn empty_ctx() -> CandidateContext {
    CandidateContext {
        commit_id: 0,
        parent_idx: 0,
        change_kind: ChangeKind::Add,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref: ByteRef::new(0, 0),
    }
}

fn packed_candidate(byte: u8) -> PackCandidate {
    PackCandidate {
        oid: oid(byte),
        ctx: empty_ctx(),
        pack_id: 0,
        offset: byte as u64,
    }
}

fn loose_candidate(byte: u8) -> LooseCandidate {
    LooseCandidate {
        oid: oid(byte),
        ctx: empty_ctx(),
    }
}

fn worker_result_with_paths(path: &[u8]) -> WorkerResult {
    let mut arena = ByteArena::with_capacity(path.len() as u32);
    if !path.is_empty() {
        arena.intern(path).expect("path intern");
    }
    WorkerResult {
        packed: Vec::new(),
        loose: Vec::new(),
        path_arena: arena,
        stats: BlobIntroStats::default(),
    }
}

#[allow(clippy::too_many_arguments)]
fn worker_result_with_loose_context(
    oid_byte: u8,
    path: &[u8],
    commit_id: u32,
    parent_idx: u8,
    change_kind: ChangeKind,
    ctx_flags: u16,
    cand_flags: u16,
) -> WorkerResult {
    let mut arena = ByteArena::with_capacity(path.len() as u32);
    let path_ref = if path.is_empty() {
        ByteRef::new(0, 0)
    } else {
        arena.intern(path).expect("path intern")
    };
    WorkerResult {
        packed: Vec::new(),
        loose: vec![LooseCandidate {
            oid: oid(oid_byte),
            ctx: CandidateContext {
                commit_id,
                parent_idx,
                change_kind,
                ctx_flags,
                cand_flags,
                path_ref,
            },
        }],
        path_arena: arena,
        stats: BlobIntroStats::default(),
    }
}

#[test]
fn seen_sets_mark_and_query() {
    let mut seen = SeenSets::new(8);
    assert!(!seen.is_tree_seen(2));
    assert!(seen.mark_tree(2));
    assert!(seen.is_tree_seen(2));
    assert!(!seen.mark_tree(2));

    assert!(!seen.is_blob_seen(3));
    assert!(seen.mark_blob(3));
    assert!(seen.is_blob_seen(3));
    assert!(!seen.mark_blob(3));
}

#[test]
fn merge_enforces_global_path_arena_capacity() {
    let workers = vec![
        worker_result_with_paths(b"abcd"),
        worker_result_with_paths(b"wxyz"),
    ];
    match merge_worker_results(workers, 6, 10, 10) {
        Err(err) => assert!(matches!(err, TreeDiffError::PathArenaFull)),
        Ok(_) => panic!("expected path cap error"),
    }
}

#[test]
fn merge_enforces_global_packed_candidate_cap() {
    let worker_a = WorkerResult {
        packed: vec![packed_candidate(1)],
        loose: Vec::new(),
        path_arena: ByteArena::with_capacity(0),
        stats: BlobIntroStats::default(),
    };
    let worker_b = WorkerResult {
        packed: vec![packed_candidate(2)],
        loose: Vec::new(),
        path_arena: ByteArena::with_capacity(0),
        stats: BlobIntroStats::default(),
    };

    match merge_worker_results(vec![worker_a, worker_b], 0, 1, 10) {
        Err(TreeDiffError::CandidateLimitExceeded {
            kind,
            max,
            observed,
        }) => {
            assert_eq!(kind, MappingCandidateKind::Packed);
            assert_eq!(max, 1);
            assert_eq!(observed, 2);
        }
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("expected packed cap error"),
    }
}

#[test]
fn per_worker_loose_limit_never_exceeds_configured_max() {
    assert_eq!(per_worker_loose_limit(0, 8), 0);
    assert_eq!(per_worker_loose_limit(3, 8), 1);
    assert_eq!(per_worker_loose_limit(100, 8), 13);
    assert_eq!(per_worker_loose_limit(100, 1), 100);
    assert!(per_worker_loose_limit(100, 8) <= 100);
    assert!(per_worker_loose_limit(3, 8) <= 3);
}

#[test]
fn merge_enforces_global_loose_candidate_cap_after_dedup() {
    let worker_a = WorkerResult {
        packed: Vec::new(),
        loose: vec![loose_candidate(1), loose_candidate(2)],
        path_arena: ByteArena::with_capacity(0),
        stats: BlobIntroStats::default(),
    };
    let worker_b = WorkerResult {
        packed: Vec::new(),
        loose: vec![loose_candidate(2), loose_candidate(3)],
        path_arena: ByteArena::with_capacity(0),
        stats: BlobIntroStats::default(),
    };

    match merge_worker_results(vec![worker_a, worker_b], 0, 10, 2) {
        Err(TreeDiffError::CandidateLimitExceeded {
            kind,
            max,
            observed,
        }) => {
            assert_eq!(kind, MappingCandidateKind::Loose);
            assert_eq!(max, 2);
            assert_eq!(observed, 3);
        }
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("expected loose cap error"),
    }
}

#[test]
fn merge_loose_dedup_uses_deterministic_context_tiebreaker() {
    let path = b"shared/path";
    let workers = vec![
        worker_result_with_loose_context(7, path, 42, 2, ChangeKind::Modify, 10, 10),
        worker_result_with_loose_context(7, path, 42, 1, ChangeKind::Modify, 10, 10),
        worker_result_with_loose_context(7, path, 42, 1, ChangeKind::Add, 11, 10),
        worker_result_with_loose_context(7, path, 42, 1, ChangeKind::Add, 1, 10),
        worker_result_with_loose_context(7, path, 42, 1, ChangeKind::Add, 1, 1),
    ];

    let merged = merge_worker_results(workers, 256, 10, 10).expect("merge succeeds");
    assert_eq!(merged.loose.len(), 1);
    let winner = merged.loose[0];
    assert_eq!(winner.ctx.commit_id, 42);
    assert_eq!(winner.ctx.parent_idx, 1);
    assert_eq!(winner.ctx.change_kind, ChangeKind::Add);
    assert_eq!(winner.ctx.ctx_flags, 1);
    assert_eq!(winner.ctx.cand_flags, 1);
    assert_eq!(merged.path_arena.get(winner.ctx.path_ref), path);
}

#[test]
fn merge_loose_dedup_is_input_order_invariant() {
    let a = worker_result_with_loose_context(9, b"zeta/path", 5, 0, ChangeKind::Add, 0, 0);
    let b = worker_result_with_loose_context(9, b"alpha/path", 5, 2, ChangeKind::Modify, 9, 9);

    let merged_ab = merge_worker_results(vec![a, b], 256, 10, 10).expect("merge succeeds");
    let merged_ba = merge_worker_results(
        vec![
            worker_result_with_loose_context(9, b"alpha/path", 5, 2, ChangeKind::Modify, 9, 9),
            worker_result_with_loose_context(9, b"zeta/path", 5, 0, ChangeKind::Add, 0, 0),
        ],
        256,
        10,
        10,
    )
    .expect("merge succeeds");

    assert_eq!(merged_ab.loose.len(), 1);
    assert_eq!(merged_ba.loose.len(), 1);

    let winner_ab = merged_ab.loose[0];
    let winner_ba = merged_ba.loose[0];
    assert_eq!(winner_ab.oid, winner_ba.oid);
    assert_eq!(winner_ab.ctx.commit_id, winner_ba.ctx.commit_id);
    assert_eq!(winner_ab.ctx.parent_idx, winner_ba.ctx.parent_idx);
    assert_eq!(winner_ab.ctx.change_kind, winner_ba.ctx.change_kind);
    assert_eq!(winner_ab.ctx.ctx_flags, winner_ba.ctx.ctx_flags);
    assert_eq!(winner_ab.ctx.cand_flags, winner_ba.ctx.cand_flags);
    assert_eq!(
        merged_ab.path_arena.get(winner_ab.ctx.path_ref),
        merged_ba.path_arena.get(winner_ba.ctx.path_ref),
    );
    assert_eq!(
        merged_ab.path_arena.get(winner_ab.ctx.path_ref),
        b"alpha/path"
    );
}

// ---------------------------------------------------------------------------
// Stub infrastructure for abort-path coverage
// ---------------------------------------------------------------------------

/// Minimal commit graph: each entry maps a commit OID to its root tree OID.
struct StubCommitGraph {
    commit_oids: Vec<OidBytes>,
    root_trees: Vec<OidBytes>,
}

impl StubCommitGraph {
    fn single(commit_oid: OidBytes, root_tree_oid: OidBytes) -> Self {
        Self {
            commit_oids: vec![commit_oid],
            root_trees: vec![root_tree_oid],
        }
    }
}

impl CommitGraph for StubCommitGraph {
    fn num_commits(&self) -> u32 {
        self.commit_oids.len() as u32
    }
    fn lookup(&self, _oid: &OidBytes) -> Result<Option<Position>, CommitPlanError> {
        Ok(None)
    }
    fn generation(&self, _pos: Position) -> u32 {
        0
    }
    fn collect_parents(
        &self,
        _pos: Position,
        _max: u32,
        scratch: &mut ParentScratch,
    ) -> Result<(), CommitPlanError> {
        scratch.clear();
        Ok(())
    }
    fn root_tree_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
        Ok(self.root_trees[pos.0 as usize])
    }
    fn commit_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
        Ok(self.commit_oids[pos.0 as usize])
    }
    fn committer_timestamp(&self, _pos: Position) -> u64 {
        0
    }
}

/// Tree source that always returns `TreeNotFound`.
///
/// No valid tree data is needed when the abort check fires before any
/// tree load attempt.
struct NeverLoadTreeSource;

impl TreeSource for NeverLoadTreeSource {
    fn load_tree(&mut self, _oid: &OidBytes) -> Result<TreeBytes, TreeDiffError> {
        Err(TreeDiffError::TreeNotFound)
    }
}

#[test]
fn merge_loose_dedup_prefers_lowest_commit_id() {
    let path = b"same/path";
    let workers = vec![
        worker_result_with_loose_context(7, path, 100, 0, ChangeKind::Add, 0, 0),
        worker_result_with_loose_context(7, path, 10, 0, ChangeKind::Add, 0, 0),
        worker_result_with_loose_context(7, path, 50, 0, ChangeKind::Add, 0, 0),
    ];

    let merged = merge_worker_results(workers, 256, 10, 10).expect("merge succeeds");
    assert_eq!(merged.loose.len(), 1);
    assert_eq!(
        merged.loose[0].ctx.commit_id, 10,
        "dedup should keep the entry with the lowest commit_id"
    );
}

// ---------------------------------------------------------------------------
// Abort-path tests
// ---------------------------------------------------------------------------

/// Pre-set abort flag causes `introduce` to return `Aborted` before loading
/// any trees. Seen sets that were marked before the call are preserved, and
/// no candidates are emitted to the sink.
#[test]
fn introduce_aborts_immediately_when_flag_is_preset() {
    // Build a minimal MIDX with one object so the OidIndex is non-empty.
    let mut midx_builder = MidxBuilder::new();
    midx_builder.add_pack(b"pack-test");
    midx_builder.add_object([0xAA; 20], 0, 0);
    let midx_data = midx_builder.build();
    let midx = MidxView::parse(&midx_data, ObjectFormat::Sha1).expect("parse test midx");
    let oid_index = OidIndex::from_midx(&midx);

    // Build a CommitGraphIndex with one commit whose root tree is the MIDX object.
    let tree_oid = OidBytes::sha1([0xAA; 20]);
    let commit_oid = OidBytes::sha1([0xBB; 20]);
    let graph = StubCommitGraph::single(commit_oid, tree_oid);
    let cg = CommitGraphIndex::build(&graph).expect("build test graph");

    let plan = [PlannedCommit {
        pos: Position(0),
        snapshot_root: false,
    }];

    let limits = TreeDiffLimits::default();
    let mut introducer = BlobIntroducer::new(&limits, 20, midx.object_count(), 16, false);

    // Pre-mark a tree index so we can verify seen state survives the abort.
    introducer.seen.mark_tree(0);
    assert!(introducer.seen.is_tree_seen(0));

    let abort = AtomicBool::new(true);
    let mut sink = CandidateBuffer::new(&limits, 20);
    let mut source = NeverLoadTreeSource;

    let result = introducer.introduce(&mut source, &cg, &plan, &oid_index, &abort, &mut sink);

    assert!(
        matches!(result, Err(TreeDiffError::Aborted)),
        "expected Aborted, got {result:?}"
    );
    assert!(
        introducer.seen.is_tree_seen(0),
        "seen sets must be preserved after abort"
    );
    assert!(
        sink.is_empty(),
        "no candidates should be emitted when aborting"
    );
}

/// `is_aborted()` returns `true` when either or both abort flags are set,
/// and `false` only when neither is set.
#[test]
fn blob_intro_worker_is_aborted_checks_both_flags() {
    let external_abort = AtomicBool::new(false);
    let error_abort = AtomicBool::new(false);
    let seen = AtomicSeenSets::new(1, 1);
    let limits = TreeDiffLimits::default();

    let worker = BlobIntroWorker::new(&limits, 20, 16, &seen, &external_abort, &error_abort, false);

    // Neither flag set.
    assert!(
        !worker.is_aborted(),
        "expected false when both flags are clear"
    );

    // Only external_abort set.
    external_abort.store(true, Ordering::Relaxed);
    assert!(
        worker.is_aborted(),
        "expected true when external_abort is set"
    );

    // Reset external, set error_abort only.
    external_abort.store(false, Ordering::Relaxed);
    error_abort.store(true, Ordering::Release);
    assert!(worker.is_aborted(), "expected true when error_abort is set");

    // Both flags set.
    external_abort.store(true, Ordering::Relaxed);
    assert!(worker.is_aborted(), "expected true when both flags are set");
}
