//! Integration tests for seen-store batching and unique blob determinism.

use std::cell::RefCell;

use scanner_git::{
    ChangeKind, CollectingUniqueBlobSink, OidBytes, SeenBlobStore, SpillError, SpillLimits, Spiller,
};
use tempfile::TempDir;

fn perf_stats_enabled() -> bool {
    cfg!(all(feature = "perf-stats", debug_assertions))
}

#[derive(Default)]
struct RecordingSeenStore {
    batches: RefCell<Vec<usize>>,
}

impl SeenBlobStore for RecordingSeenStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        self.batches.borrow_mut().push(oids.len());
        Ok(vec![false; oids.len()])
    }
}

#[test]
fn seen_store_batches_by_count() {
    let mut limits = SpillLimits::RESTRICTIVE;
    limits.max_chunk_candidates = 32;
    limits.max_chunk_path_bytes = 1024;
    limits.max_path_len = 16;
    limits.seen_batch_max_oids = 3;
    limits.seen_batch_max_path_bytes = 64;

    let tmp = TempDir::new().unwrap();
    let mut spiller = Spiller::new(limits, 20, tmp.path()).unwrap();

    for i in 0..7u8 {
        let oid = OidBytes::sha1([i; 20]);
        spiller
            .push(oid, b"a", 1, 0, ChangeKind::Add, 0, 0)
            .unwrap();
    }

    let store = RecordingSeenStore::default();
    let mut sink = CollectingUniqueBlobSink::default();
    let stats = spiller.finalize(&store, &mut sink).unwrap();

    assert_eq!(store.batches.borrow().as_slice(), &[3, 3, 1]);
    if perf_stats_enabled() {
        assert_eq!(stats.emitted_blobs, 7);
    } else {
        assert_eq!(stats.emitted_blobs, 0);
    }
    assert_eq!(sink.blobs.len(), 7);
}

struct CandidateInput {
    oid: OidBytes,
    path: &'static [u8],
    commit_id: u32,
    parent_idx: u8,
    change_kind: ChangeKind,
    ctx_flags: u16,
    cand_flags: u16,
}

fn run_spiller(
    limits: SpillLimits,
    candidates: &[CandidateInput],
) -> Vec<scanner_git::CollectedUniqueBlob> {
    let tmp = TempDir::new().unwrap();
    let mut spiller = Spiller::new(limits, 20, tmp.path()).unwrap();

    for cand in candidates {
        spiller
            .push(
                cand.oid,
                cand.path,
                cand.commit_id,
                cand.parent_idx,
                cand.change_kind,
                cand.ctx_flags,
                cand.cand_flags,
            )
            .unwrap();
    }

    let mut sink = CollectingUniqueBlobSink::default();
    let _stats = spiller
        .finalize(&scanner_git::NeverSeenStore, &mut sink)
        .unwrap();
    sink.blobs
}

#[test]
fn unique_blob_output_deterministic_across_spills() {
    let oid_a = OidBytes::sha1([0x11; 20]);
    let oid_b = OidBytes::sha1([0x22; 20]);

    let candidates = vec![
        CandidateInput {
            oid: oid_a,
            path: b"a.txt",
            commit_id: 5,
            parent_idx: 0,
            change_kind: ChangeKind::Modify,
            ctx_flags: 1,
            cand_flags: 2,
        },
        CandidateInput {
            oid: oid_b,
            path: b"z.txt",
            commit_id: 1,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
        },
        CandidateInput {
            oid: oid_a,
            path: b"z.txt",
            commit_id: 3,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
        },
        CandidateInput {
            oid: oid_a,
            path: b"b.txt",
            commit_id: 7,
            parent_idx: 0,
            change_kind: ChangeKind::Modify,
            ctx_flags: 0,
            cand_flags: 0,
        },
        CandidateInput {
            oid: oid_b,
            path: b"y.txt",
            commit_id: 1,
            parent_idx: 1,
            change_kind: ChangeKind::Modify,
            ctx_flags: 3,
            cand_flags: 1,
        },
    ];

    let mut limits_small = SpillLimits::RESTRICTIVE;
    limits_small.max_chunk_candidates = 2;
    limits_small.max_chunk_path_bytes = 64;
    limits_small.max_path_len = 32;
    limits_small.seen_batch_max_oids = 2;
    limits_small.seen_batch_max_path_bytes = 64;

    let mut limits_large = limits_small;
    limits_large.max_chunk_candidates = 32;
    limits_large.max_chunk_path_bytes = 1024;

    let out_small = run_spiller(limits_small, &candidates);
    let out_large = run_spiller(limits_large, &candidates);

    assert_eq!(out_small, out_large);
    assert_eq!(out_small.len(), 2);

    assert_eq!(out_small[0].oid, oid_a);
    assert_eq!(out_small[0].ctx.commit_id, 3);
    assert_eq!(out_small[0].path, b"z.txt");

    assert_eq!(out_small[1].oid, oid_b);
    assert_eq!(out_small[1].ctx.commit_id, 1);
    assert_eq!(out_small[1].path, b"y.txt");
}
