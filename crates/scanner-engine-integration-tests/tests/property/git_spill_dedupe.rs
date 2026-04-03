//! Property tests for spill run merge/dedupe.
//!
//! The merged output should match a naive in-memory sort+dedupe across all
//! records, regardless of how they are partitioned into runs.
//!
//! # Invariants
//! - Spill partitioning does not change canonical context selection.
//! - Input ordering does not affect canonical tie-break outcomes.
//! - Runs are written in sorted+deduped form (as the on-disk format expects).

use std::collections::BTreeMap;
use std::io::Cursor;

use proptest::prelude::*;
use tempfile::TempDir;

use scanner_git::{
    ChangeKind, CollectedUniqueBlob, CollectingUniqueBlobSink, NeverSeenStore, OidBytes,
    SpillLimits, Spiller,
};
use scanner_git::{RunContext, RunHeader, RunMerger, RunReader, RunRecord, RunWriter};

/// Generates run records suitable for round-tripping through `RunWriter`.
///
/// Paths are short ASCII to keep run sizes small while still exercising
/// ordering and dedupe behavior across OID/path/context combinations.
fn record_strategy() -> impl Strategy<Value = RunRecord> {
    // Keep paths short and ASCII to avoid blowing up run sizes while still
    // exercising ordering and dedupe across OID/path/context combinations.
    let oid = prop::array::uniform20(any::<u8>()).prop_map(OidBytes::sha1);
    let path = "[a-z]{1,6}".prop_map(|s| s.into_bytes());
    let commit_id = any::<u32>();
    let parent_idx = any::<u8>();
    let change_kind = any::<bool>();
    let ctx_flags = any::<u16>();
    let cand_flags = any::<u16>();

    (
        oid,
        path,
        commit_id,
        parent_idx,
        change_kind,
        ctx_flags,
        cand_flags,
    )
        .prop_map(
            |(oid, path, commit_id, parent_idx, change_kind, ctx_flags, cand_flags)| RunRecord {
                oid,
                ctx: RunContext {
                    commit_id,
                    parent_idx,
                    change_kind: if change_kind {
                        ChangeKind::Add
                    } else {
                        ChangeKind::Modify
                    },
                    ctx_flags,
                    cand_flags,
                },
                path,
            },
        )
}

/// Serializes a run in sorted+deduped order, matching writer requirements.
fn write_run(records: &[RunRecord]) -> Vec<u8> {
    // The on-disk format expects sorted+deduped input; emulate that here.
    let mut run_records = records.to_vec();
    run_records.sort();
    run_records.dedup();

    let header = RunHeader::new(20, run_records.len() as u32).unwrap();
    let mut buf = Vec::new();
    let mut writer = RunWriter::new(&mut buf, header).unwrap();
    for record in &run_records {
        writer.write_record(record).unwrap();
    }
    writer.finish().unwrap();
    buf
}

/// Canonical candidate input shape for spill/dedupe tests.
#[derive(Clone, Debug)]
struct CandidateInput {
    oid: OidBytes,
    path: Vec<u8>,
    commit_id: u32,
    parent_idx: u8,
    change_kind: ChangeKind,
    ctx_flags: u16,
    cand_flags: u16,
}

/// Canonicalized output shape for comparing expected vs actual spill output.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalOut {
    oid: OidBytes,
    path: Vec<u8>,
    commit_id: u32,
    parent_idx: u8,
    change_kind: ChangeKind,
    ctx_flags: u16,
    cand_flags: u16,
}

impl From<&CandidateInput> for CanonicalOut {
    fn from(cand: &CandidateInput) -> Self {
        Self {
            oid: cand.oid,
            path: cand.path.clone(),
            commit_id: cand.commit_id,
            parent_idx: cand.parent_idx,
            change_kind: cand.change_kind,
            ctx_flags: cand.ctx_flags,
            cand_flags: cand.cand_flags,
        }
    }
}

impl From<CollectedUniqueBlob> for CanonicalOut {
    fn from(blob: CollectedUniqueBlob) -> Self {
        Self {
            oid: blob.oid,
            path: blob.path,
            commit_id: blob.ctx.commit_id,
            parent_idx: blob.ctx.parent_idx,
            change_kind: blob.ctx.change_kind,
            ctx_flags: blob.ctx.ctx_flags,
            cand_flags: blob.ctx.cand_flags,
        }
    }
}

/// Produces candidates with a constrained domain to encourage collisions.
///
/// Small OID/path/value spaces maximize dedupe and canonical tie-break cases.
fn candidate_strategy() -> impl Strategy<Value = CandidateInput> {
    let oid_byte = 0u8..=4;
    let path = prop::string::string_regex("[a-z]{1,6}")
        .unwrap()
        .prop_map(|s| s.into_bytes());
    let commit_id = 0u32..16;
    let parent_idx = 0u8..4;
    let change_kind = prop_oneof![Just(ChangeKind::Add), Just(ChangeKind::Modify)];
    let ctx_flags = 0u16..8;
    let cand_flags = 0u16..8;

    (
        oid_byte,
        path,
        commit_id,
        parent_idx,
        change_kind,
        ctx_flags,
        cand_flags,
    )
        .prop_map(
            |(oid_byte, path, commit_id, parent_idx, change_kind, ctx_flags, cand_flags)| {
                CandidateInput {
                    oid: OidBytes::sha1([oid_byte; 20]),
                    path,
                    commit_id,
                    parent_idx,
                    change_kind,
                    ctx_flags,
                    cand_flags,
                }
            },
        )
}

/// Returns true if `a` wins the canonical tie-break against `b`.
///
/// This ordering matches the spill/dedupe canonicalization rules.
fn is_more_canonical(a: &CandidateInput, b: &CandidateInput) -> bool {
    (
        a.commit_id,
        a.path.as_slice(),
        a.parent_idx,
        a.change_kind.as_u8(),
        a.ctx_flags,
        a.cand_flags,
    ) < (
        b.commit_id,
        b.path.as_slice(),
        b.parent_idx,
        b.change_kind.as_u8(),
        b.ctx_flags,
        b.cand_flags,
    )
}

/// Computes the expected canonical output using an in-memory map.
///
/// This is the "oracle" used to validate spill/dedupe behavior.
fn canonical_expected(candidates: &[CandidateInput]) -> Vec<CanonicalOut> {
    let mut best: BTreeMap<OidBytes, CandidateInput> = BTreeMap::new();
    for cand in candidates {
        best.entry(cand.oid)
            .and_modify(|current| {
                if is_more_canonical(cand, current) {
                    *current = cand.clone();
                }
            })
            .or_insert_with(|| cand.clone());
    }
    best.into_values()
        .map(|cand| CanonicalOut::from(&cand))
        .collect()
}

/// Constructs spill limits that control partition size for tests.
///
/// The limits are tuned to exercise multi-run spill behavior deterministically.
fn partition_limits(max_chunk_candidates: u32, max_chunk_path_bytes: u32) -> SpillLimits {
    const MAX_PATH_LEN: u16 = 32;

    let mut limits = SpillLimits::RESTRICTIVE;
    limits.max_path_len = MAX_PATH_LEN;
    limits.max_chunk_candidates = max_chunk_candidates;
    limits.max_chunk_path_bytes = max_chunk_path_bytes.max(MAX_PATH_LEN as u32);
    limits.max_spill_runs = 256;
    limits.max_spill_bytes = 128 * 1024 * 1024;
    limits.seen_batch_max_oids = 128;
    limits.seen_batch_max_path_bytes = 4 * 1024;
    limits
}

/// Limits that force many small runs.
fn small_limits() -> SpillLimits {
    partition_limits(1, 64)
}

/// Limits that allow larger runs and fewer spill partitions.
fn large_limits() -> SpillLimits {
    partition_limits(512, 16 * 1024)
}

/// Executes the spill/dedupe pipeline and returns canonicalized output.
fn run_spiller(limits: SpillLimits, candidates: &[CandidateInput]) -> Vec<CanonicalOut> {
    let tmp = TempDir::new().unwrap();
    let mut spiller = Spiller::new(limits, 20, tmp.path()).unwrap();

    for cand in candidates {
        spiller
            .push(
                cand.oid,
                &cand.path,
                cand.commit_id,
                cand.parent_idx,
                cand.change_kind,
                cand.ctx_flags,
                cand.cand_flags,
            )
            .unwrap();
    }

    let mut sink = CollectingUniqueBlobSink::default();
    spiller
        .finalize(
            &NeverSeenStore,
            &scanner_git::NullSeenBitmapPersister,
            &mut sink,
        )
        .unwrap();
    sink.blobs.into_iter().map(CanonicalOut::from).collect()
}

proptest! {
    #[test]
    fn spill_merge_matches_naive(
        records in prop::collection::vec(record_strategy(), 1..50),
        run_count in 1usize..6,
    ) {
        // Naive reference: all records combined, then globally sorted+deduped.
        let mut expected = records.clone();
        expected.sort();
        expected.dedup();

        let mut runs: Vec<Vec<RunRecord>> = vec![Vec::new(); run_count];
        for (idx, rec) in records.into_iter().enumerate() {
            runs[idx % run_count].push(rec);
        }

        let mut readers = Vec::new();
        for run in runs {
            let buf = write_run(&run);
            let reader = RunReader::new(Cursor::new(buf), 8192).unwrap();
            readers.push(reader);
        }

        // Merge should preserve global ordering and suppress duplicates.
        let mut merger = RunMerger::new(readers).unwrap();
        let mut actual = Vec::new();
        while let Some(record) = merger.next_unique().unwrap() {
            actual.push(record.clone());
        }

        prop_assert_eq!(actual, expected);
    }
}

proptest! {
    #[test]
    fn spill_partition_invariance(
        candidates in prop::collection::vec(candidate_strategy(), 1..50),
    ) {
        let expected = canonical_expected(&candidates);
        let out_small = run_spiller(small_limits(), &candidates);
        let out_large = run_spiller(large_limits(), &candidates);

        prop_assert_eq!(&out_small, &out_large);
        prop_assert_eq!(&out_small, &expected);
    }

    #[test]
    fn canonical_context_stable_under_input_order(
        candidates in prop::collection::vec(candidate_strategy(), 1..50),
    ) {
        let expected = canonical_expected(&candidates);
        let out_forward = run_spiller(small_limits(), &candidates);

        let mut reversed = candidates.clone();
        reversed.reverse();
        let out_reversed = run_spiller(small_limits(), &reversed);

        prop_assert_eq!(&out_forward, &expected);
        prop_assert_eq!(&out_forward, &out_reversed);
    }
}
