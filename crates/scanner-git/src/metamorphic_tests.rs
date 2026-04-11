//! Metamorphic tests for pack object resolution.
//!
//! These tests compare related executions that should decode identical bytes
//! even when cache state, MIDX pack ordering, or pack set membership changes.

use std::collections::HashMap;

use proptest::prelude::*;
use tempfile::tempdir;

use crate::byte_arena::{ByteArena, ByteRef};
use crate::delta_test_helpers::{make_add_delta, make_mixed_delta, SyntheticPackBuilder};
use crate::multi_pack_test_helpers::{stable_oid, test_limits, MultiPackFixture};
use crate::object_id::OidBytes;
use crate::pack_cache::PackCache;
use crate::pack_candidates::PackCandidate;
use crate::pack_decode::PackDecodeLimits;
use crate::pack_exec::{
    execute_pack_plan, ExternalBase, ExternalBaseProvider, PackExecError, PackExecReport,
    PackObjectSink,
};
use crate::pack_inflate::ObjectKind;
use crate::pack_io::PackIoError;
use crate::pack_plan::{build_pack_plans, OidResolver, PackPlanConfig, PackPlanError, PackView};
use crate::pack_plan_model::PackPlan;
use crate::test_utils::{for_each_permutation, proptest_cases};
use crate::tree_candidate::{CandidateContext, ChangeKind};

const PROPTEST_CASES: u32 = 8;
const CACHE_BYTES: u32 = 256 * 1024;
const PACK_ID: u16 = 0;
const PATH_ARENA_BYTES: u32 = 128;
const DECODE_LIMITS: PackDecodeLimits = PackDecodeLimits::new(64, 1024, 1024);

#[derive(Default)]
struct CollectingSink {
    blobs: HashMap<OidBytes, Vec<u8>>,
}

impl PackObjectSink for CollectingSink {
    fn emit(
        &mut self,
        candidate: &PackCandidate,
        _path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        self.blobs.insert(candidate.oid, bytes.to_vec());
        Ok(())
    }
}

#[derive(Default)]
struct UnexpectedExternalLookup;

impl ExternalBaseProvider for UnexpectedExternalLookup {
    fn load_base(&mut self, _oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
        panic!("single-pack metamorphic tests should not perform external base lookups");
    }
}

struct MissingResolver;

impl OidResolver for MissingResolver {
    fn resolve(&self, _oid: &OidBytes) -> Result<Option<(u16, u64)>, PackPlanError> {
        Ok(None)
    }
}

fn ctx(path_ref: ByteRef) -> CandidateContext {
    CandidateContext {
        commit_id: 1,
        parent_idx: 0,
        change_kind: ChangeKind::Add,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref,
    }
}

fn candidate(path_ref: ByteRef, oid: OidBytes, offset: u64) -> PackCandidate {
    PackCandidate {
        oid,
        ctx: ctx(path_ref),
        pack_id: PACK_ID,
        offset,
    }
}

fn single_pack_plan(pack_bytes: &[u8], candidates: Vec<PackCandidate>) -> PackPlan {
    let pack = PackView::parse(pack_bytes, OidBytes::SHA1_LEN).expect("single-pack test pack");
    let config = PackPlanConfig {
        max_delta_depth: 8,
        ..PackPlanConfig::default()
    };
    let mut plans = build_pack_plans(candidates, &[Some(pack)], &MissingResolver, &config)
        .expect("single-pack test plan");
    assert_eq!(
        plans.len(),
        1,
        "single-pack tests should produce exactly one plan"
    );
    plans.pop().expect("single-pack test plan")
}

fn execute_collect(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    cache: &mut PackCache,
) -> (HashMap<OidBytes, Vec<u8>>, PackExecReport) {
    let mut sink = CollectingSink::default();
    let mut external = UnexpectedExternalLookup;
    let spill_dir = tempdir().expect("spill tempdir");
    let report = execute_pack_plan(
        plan,
        pack_bytes,
        paths,
        &DECODE_LIMITS,
        cache,
        &mut external,
        &mut sink,
        spill_dir.path(),
    )
    .expect("execute_pack_plan");
    (sink.blobs, report)
}

fn resolve_via_pack_io(
    fixture: &MultiPackFixture,
    oid: &OidBytes,
) -> Result<(ObjectKind, Vec<u8>), PackIoError> {
    let mut pack_io = fixture.pack_io(test_limits())?;
    let loaded = pack_io.load_object(oid)?;
    Ok(loaded.expect("fixture object should resolve"))
}

fn build_permuted_fixture(order: &[usize]) -> (MultiPackFixture, OidBytes, Vec<u8>) {
    let mut builder = MultiPackFixture::builder();
    let mut packs = [None; 3];
    for &idx in order {
        let name = match idx {
            0 => b"pack-a".as_slice(),
            1 => b"pack-b".as_slice(),
            2 => b"pack-c".as_slice(),
            _ => panic!("unexpected logical pack index {idx}"),
        };
        packs[idx] = Some(builder.add_pack(name));
    }

    let pack_a = packs[0].expect("pack-a");
    let pack_b = packs[1].expect("pack-b");
    let pack_c = packs[2].expect("pack-c");

    let base = builder.add_blob(pack_b, b"perm-base");
    let target = builder.add_ref_delta_mixed(pack_a, base, 9, b"-leaf");
    let _noise = builder.add_blob(pack_c, b"perm-noise");

    let fixture = builder.build().expect("permutation fixture");
    let expected = fixture
        .expected(target)
        .expect("permutation target bytes")
        .1
        .to_vec();
    let oid = fixture.oid(target);
    (fixture, oid, expected)
}

fn delta_equivalence_case() -> impl Strategy<Value = (Vec<u8>, usize, Vec<u8>)> {
    prop::collection::vec(any::<u8>(), 1..=64usize).prop_flat_map(|base| {
        let base_len = base.len();
        (
            Just(base),
            1..=base_len,
            prop::collection::vec(any::<u8>(), 0..=32usize),
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases(PROPTEST_CASES)))]

    #[test]
    fn cache_bypass_equivalence(
        base_bytes in prop::collection::vec(any::<u8>(), 0..=32usize),
        mid_bytes in prop::collection::vec(any::<u8>(), 1..=64usize),
        leaf_bytes in prop::collection::vec(any::<u8>(), 1..=64usize),
        sibling_bytes in prop::collection::vec(any::<u8>(), 1..=64usize),
    ) {
        let mut builder = SyntheticPackBuilder::new();
        let base_idx = builder.add_non_delta(3, &base_bytes);
        let mid_idx = builder.add_ofs_delta(base_idx, &make_add_delta(base_bytes.len(), &mid_bytes));
        let leaf_idx = builder.add_ofs_delta(mid_idx, &make_add_delta(mid_bytes.len(), &leaf_bytes));
        let sibling_idx = builder.add_ofs_delta(base_idx, &make_add_delta(base_bytes.len(), &sibling_bytes));
        let (pack_bytes, offsets) = builder.build();

        let mut arena = ByteArena::with_capacity(PATH_ARENA_BYTES);
        let path_ref = arena.intern(b"metamorphic/cache.bin").expect("path");
        let base_oid = stable_oid(b"cache-base");
        let mid_oid = stable_oid(b"cache-mid");
        let leaf_oid = stable_oid(b"cache-leaf");
        let sibling_oid = stable_oid(b"cache-sibling");
        let plan = single_pack_plan(
            &pack_bytes,
            vec![
                candidate(path_ref, base_oid, offsets[base_idx]),
                candidate(path_ref, mid_oid, offsets[mid_idx]),
                candidate(path_ref, leaf_oid, offsets[leaf_idx]),
                candidate(path_ref, sibling_oid, offsets[sibling_idx]),
            ],
        );

        let mut no_cache = PackCache::new(0);
        let (cache_off, off_report) = execute_collect(&plan, &pack_bytes, &arena, &mut no_cache);
        prop_assert!(off_report.skips.is_empty());
        prop_assert!(no_cache.get(offsets[base_idx]).is_none());

        let mut warmed_cache = PackCache::new(CACHE_BYTES);
        let (cache_on_cold, cold_report) = execute_collect(&plan, &pack_bytes, &arena, &mut warmed_cache);
        prop_assert!(cold_report.skips.is_empty());
        prop_assert!(warmed_cache.get(offsets[leaf_idx]).is_some());

        let (cache_on_warm, warm_report) = execute_collect(&plan, &pack_bytes, &arena, &mut warmed_cache);
        prop_assert!(warm_report.skips.is_empty());

        prop_assert_eq!(&cache_off, &cache_on_cold);
        prop_assert_eq!(&cache_off, &cache_on_warm);
        prop_assert_eq!(cache_on_warm.get(&base_oid), Some(&base_bytes));
        prop_assert_eq!(cache_on_warm.get(&mid_oid), Some(&mid_bytes));
        prop_assert_eq!(cache_on_warm.get(&leaf_oid), Some(&leaf_bytes));
        prop_assert_eq!(cache_on_warm.get(&sibling_oid), Some(&sibling_bytes));
    }

    #[test]
    fn delta_chain_equivalence((base_bytes, copy_len, suffix) in delta_equivalence_case()) {
        let mut result_bytes = base_bytes[..copy_len].to_vec();
        result_bytes.extend_from_slice(&suffix);

        let mut builder = SyntheticPackBuilder::new();
        let base_idx = builder.add_non_delta(3, &base_bytes);
        let non_delta_idx = builder.add_non_delta(3, &result_bytes);
        let delta_idx = builder.add_ofs_delta(
            base_idx,
            &make_mixed_delta(base_bytes.len(), 0, copy_len, &suffix),
        );
        let (pack_bytes, offsets) = builder.build();

        let mut arena = ByteArena::with_capacity(PATH_ARENA_BYTES);
        let path_ref = arena.intern(b"metamorphic/delta.bin").expect("path");
        let non_delta_oid = stable_oid(b"delta-equivalence/non-delta");
        let delta_oid = stable_oid(b"delta-equivalence/delta");
        let plan = single_pack_plan(
            &pack_bytes,
            vec![
                candidate(path_ref, non_delta_oid, offsets[non_delta_idx]),
                candidate(path_ref, delta_oid, offsets[delta_idx]),
            ],
        );

        let mut cache = PackCache::new(CACHE_BYTES);
        let (resolved, report) = execute_collect(&plan, &pack_bytes, &arena, &mut cache);
        prop_assert!(report.skips.is_empty());
        prop_assert_eq!(resolved.get(&non_delta_oid), Some(&result_bytes));
        prop_assert_eq!(resolved.get(&delta_oid), Some(&result_bytes));
    }
}

#[test]
fn permutation_invariance() {
    let mut order = [0usize, 1, 2];
    let (baseline_fixture, baseline_oid, baseline_bytes) = build_permuted_fixture(&order);
    let baseline = resolve_via_pack_io(&baseline_fixture, &baseline_oid).expect("baseline fixture");
    assert_eq!(baseline.0, ObjectKind::Blob);
    assert_eq!(baseline.1, baseline_bytes);

    for_each_permutation(&mut order, 0, &mut |perm| {
        let (fixture, oid, expected) = build_permuted_fixture(perm);
        let resolved = resolve_via_pack_io(&fixture, &oid).expect("permuted fixture");
        assert_eq!(oid, baseline_oid);
        assert_eq!(resolved.0, ObjectKind::Blob);
        assert_eq!(resolved.1, expected);
        assert_eq!(resolved.1, baseline.1);
    });
}

#[test]
fn subset_consistency() {
    let mut full_builder = MultiPackFixture::builder();
    let pack_a = full_builder.add_pack(b"pack-a");
    let pack_b = full_builder.add_pack(b"pack-b");
    let pack_c = full_builder.add_pack(b"pack-c");
    let base_a = full_builder.add_blob(pack_a, b"subset-base");
    let target_full = full_builder.add_ofs_delta(pack_a, base_a, b"subset-leaf");
    let _noise_b = full_builder.add_blob(pack_b, b"subset-noise-b");
    let _noise_c = full_builder.add_blob(pack_c, b"subset-noise-c");
    let full_fixture = full_builder.build().expect("full fixture");

    let mut subset_builder = MultiPackFixture::builder();
    let subset_pack_a = subset_builder.add_pack(b"pack-a");
    let subset_base_a = subset_builder.add_blob(subset_pack_a, b"subset-base");
    let target_subset = subset_builder.add_ofs_delta(subset_pack_a, subset_base_a, b"subset-leaf");
    let subset_fixture = subset_builder.build().expect("subset fixture");

    let full_oid = full_fixture.oid(target_full);
    let subset_oid = subset_fixture.oid(target_subset);
    assert_eq!(full_oid, subset_oid);

    let full_resolved = resolve_via_pack_io(&full_fixture, &full_oid).expect("full resolution");
    let subset_resolved =
        resolve_via_pack_io(&subset_fixture, &subset_oid).expect("subset resolution");

    assert_eq!(full_resolved.0, ObjectKind::Blob);
    assert_eq!(subset_resolved.0, ObjectKind::Blob);
    assert_eq!(full_resolved, subset_resolved);
    assert_eq!(full_resolved.1, b"subset-leaf");
}
