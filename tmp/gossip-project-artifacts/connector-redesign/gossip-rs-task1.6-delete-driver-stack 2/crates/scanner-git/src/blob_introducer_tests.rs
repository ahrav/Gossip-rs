use super::{merge_worker_results, per_worker_loose_limit, BlobIntroStats, SeenSets, WorkerResult};
use crate::byte_arena::{ByteArena, ByteRef};
use crate::errors::{MappingCandidateKind, TreeDiffError};
use crate::object_id::OidBytes;
use crate::pack_candidates::{LooseCandidate, PackCandidate};
use crate::tree_candidate::{CandidateContext, ChangeKind};

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
