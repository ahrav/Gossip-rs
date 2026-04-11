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
use crate::pack_exec::{execute_pack_plan, PackExecReport};
use crate::pack_exec_test_helpers::{
    default_test_ctx as ctx, CollectingSink, NoExternal, TEST_DECODE_LIMITS,
};
use crate::pack_inflate::ObjectKind;
use crate::pack_plan::{build_pack_plans, PackPlanConfig, PackPlanError, PackView};
use crate::pack_plan_model::PackPlan;
use crate::test_utils::{for_each_permutation, proptest_cases};
use crate::tree_candidate::ChangeKind;

/// Proptest iteration count — low because each case builds full pack plans.
const PROPTEST_CASES: u32 = 8;
/// Cache capacity for warmed-cache test paths (256 KiB).
const CACHE_BYTES: u32 = 256 * 1024;
/// All single-pack helpers use pack index 0.
const PACK_ID: u16 = 0;
/// Byte arena budget — sufficient for the short synthetic paths in these tests.
const PATH_ARENA_BYTES: u32 = 128;

/// OID resolver that always returns `None`.
///
/// Suitable for single-pack tests where all delta chains use OFS encoding
/// and no REF_DELTA base resolution is needed.
struct NullResolver;

impl crate::pack_plan::OidResolver for NullResolver {
    fn resolve(&self, _oid: &OidBytes) -> Result<Option<(u16, u64)>, PackPlanError> {
        Ok(None)
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

/// Builds a single-pack plan from raw pack bytes and candidates.
///
/// Uses [`NullResolver`], so this helper is only suitable for packs where
/// all delta chains use OFS encoding. REF deltas will be treated as
/// external dependencies.
fn single_pack_plan(pack_bytes: &[u8], candidates: Vec<PackCandidate>) -> PackPlan {
    let pack = PackView::parse(pack_bytes, OidBytes::SHA1_LEN).expect("single-pack test pack");
    let config = PackPlanConfig {
        max_delta_depth: 8,
        ..PackPlanConfig::default()
    };
    let mut plans = build_pack_plans(candidates, &[Some(pack)], &NullResolver, &config)
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
    let mut external = NoExternal;
    let spill_dir = tempdir().expect("spill tempdir");
    let report = execute_pack_plan(
        plan,
        pack_bytes,
        paths,
        &TEST_DECODE_LIMITS,
        cache,
        &mut external,
        &mut sink,
        spill_dir.path(),
    )
    .expect("execute_pack_plan");
    (sink.blobs, report)
}

fn resolve_via_pack_io(fixture: &MultiPackFixture, oid: &OidBytes) -> (ObjectKind, Vec<u8>) {
    let mut pack_io = fixture.pack_io(test_limits()).expect("fixture pack_io");
    pack_io
        .load_object(oid)
        .expect("fixture load_object")
        .unwrap_or_else(|| panic!("fixture object {oid:?} should resolve"))
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
            prop::collection::vec(any::<u8>(), 1..=32usize),
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(proptest_cases(PROPTEST_CASES)))]

    /// Verifies that resolved bytes are identical regardless of cache state.
    ///
    /// Runs the same plan three times (no cache, cold cache, warm cache) and
    /// a fourth warm pass to confirm idempotence. Uses a mixed delta for
    /// `mid` so the resolved content depends on base bytes — a base
    /// resolution bug would surface as a ground-truth mismatch.
    #[test]
    fn cache_bypass_equivalence(
        base_bytes in prop::collection::vec(any::<u8>(), 1..=32usize),
        mid_bytes in prop::collection::vec(any::<u8>(), 1..=64usize),
        leaf_bytes in prop::collection::vec(any::<u8>(), 1..=64usize),
        sibling_bytes in prop::collection::vec(any::<u8>(), 1..=64usize),
    ) {
        // mid copies the first half of base then appends mid_bytes, so
        // resolved content depends on actual base content.
        let mid_copy_len = base_bytes.len().div_ceil(2);
        let mut expected_mid = base_bytes[..mid_copy_len].to_vec();
        expected_mid.extend_from_slice(&mid_bytes);

        let mut builder = SyntheticPackBuilder::new();
        let base_idx = builder.add_non_delta(3, &base_bytes);
        let mid_idx = builder.add_ofs_delta(
            base_idx,
            &make_mixed_delta(base_bytes.len(), 0, mid_copy_len, &mid_bytes),
        );
        let leaf_idx = builder.add_ofs_delta(mid_idx, &make_add_delta(expected_mid.len(), &leaf_bytes));
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

        // Run 1: no cache.
        let mut no_cache = PackCache::new(0);
        let (cache_off, off_report) = execute_collect(&plan, &pack_bytes, &arena, &mut no_cache);
        prop_assert!(off_report.skips.is_empty());
        prop_assert_eq!(cache_off.len(), 4);
        prop_assert!(no_cache.get(offsets[base_idx]).is_none());

        // Run 2: cold cache (first population).
        let mut warmed_cache = PackCache::new(CACHE_BYTES);
        let (cache_on_cold, cold_report) = execute_collect(&plan, &pack_bytes, &arena, &mut warmed_cache);
        prop_assert!(cold_report.skips.is_empty());
        prop_assert_eq!(cache_on_cold.len(), 4);
        prop_assert!(warmed_cache.get(offsets[leaf_idx]).is_some());

        // Run 3: warm cache (hits existing entries).
        let (cache_on_warm, warm_report) = execute_collect(&plan, &pack_bytes, &arena, &mut warmed_cache);
        prop_assert!(warm_report.skips.is_empty());
        prop_assert_eq!(cache_on_warm.len(), 4);

        // Run 4: second warm pass — idempotence check.
        let (cache_on_warm2, warm2_report) = execute_collect(&plan, &pack_bytes, &arena, &mut warmed_cache);
        prop_assert!(warm2_report.skips.is_empty());
        prop_assert_eq!(cache_on_warm2.len(), 4);

        // Metamorphic equivalence: all four runs produce identical blobs.
        prop_assert_eq!(&cache_off, &cache_on_cold);
        prop_assert_eq!(&cache_off, &cache_on_warm);
        prop_assert_eq!(&cache_off, &cache_on_warm2);

        // Ground-truth: resolved content matches expected values.
        prop_assert_eq!(cache_on_warm.get(&base_oid), Some(&base_bytes));
        prop_assert_eq!(cache_on_warm.get(&mid_oid), Some(&expected_mid));
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
    let baseline = resolve_via_pack_io(&baseline_fixture, &baseline_oid);
    assert_eq!(baseline.0, ObjectKind::Blob);
    assert_eq!(baseline.1, baseline_bytes);

    // Generates all 6 permutations including identity — the identity overlap
    // with the baseline is harmless and not worth special-casing.
    for_each_permutation(&mut order, 0, &mut |perm| {
        let (fixture, oid, expected) = build_permuted_fixture(perm);
        let resolved = resolve_via_pack_io(&fixture, &oid);
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
    // Mixed delta: copies 6 bytes from base ("subset") then appends "-leaf",
    // so resolved content = "subset-leaf" and depends on actual base bytes.
    let target_full = full_builder.add_ofs_delta_mixed(pack_a, base_a, 6, b"-leaf");
    let _noise_b = full_builder.add_blob(pack_b, b"subset-noise-b");
    let _noise_c = full_builder.add_blob(pack_c, b"subset-noise-c");
    let full_fixture = full_builder.build().expect("full fixture");

    let mut subset_builder = MultiPackFixture::builder();
    let subset_pack_a = subset_builder.add_pack(b"pack-a");
    let subset_base_a = subset_builder.add_blob(subset_pack_a, b"subset-base");
    let target_subset =
        subset_builder.add_ofs_delta_mixed(subset_pack_a, subset_base_a, 6, b"-leaf");
    let subset_fixture = subset_builder.build().expect("subset fixture");

    let full_oid = full_fixture.oid(target_full);
    let subset_oid = subset_fixture.oid(target_subset);
    assert_eq!(full_oid, subset_oid);

    let full_resolved = resolve_via_pack_io(&full_fixture, &full_oid);
    let subset_resolved = resolve_via_pack_io(&subset_fixture, &subset_oid);

    assert_eq!(full_resolved.0, ObjectKind::Blob);
    assert_eq!(subset_resolved.0, ObjectKind::Blob);
    assert_eq!(full_resolved, subset_resolved);
    assert_eq!(full_resolved.1, b"subset-leaf");
}

/// Verifies that OFS_DELTA and REF_DELTA produce identical resolved bytes
/// for the same logical delta operation.
///
/// OFS_DELTA uses an intra-pack backward offset to locate the base.
/// REF_DELTA uses an OID that the executor resolves through the MIDX and
/// an external base provider. Despite these distinct code paths, the
/// resolved content must be byte-identical.
#[test]
fn ref_delta_ofs_delta_equivalence() {
    // OFS path: base and delta in the same pack.
    let mut ofs_builder = MultiPackFixture::builder();
    let ofs_pack = ofs_builder.add_pack(b"pack-ofs");
    let ofs_base = ofs_builder.add_blob(ofs_pack, b"delta-encoding-base");
    let ofs_target = ofs_builder.add_ofs_delta_mixed(ofs_pack, ofs_base, 14, b"-ofs");
    let ofs_fixture = ofs_builder.build().expect("OFS fixture");

    // REF path: base in pack-b, delta in pack-a (cross-pack REF_DELTA).
    let mut ref_builder = MultiPackFixture::builder();
    let ref_pack_a = ref_builder.add_pack(b"pack-ref-a");
    let ref_pack_b = ref_builder.add_pack(b"pack-ref-b");
    let ref_base = ref_builder.add_blob(ref_pack_b, b"delta-encoding-base");
    let ref_target = ref_builder.add_ref_delta_mixed(ref_pack_a, ref_base, 14, b"-ofs");
    let ref_fixture = ref_builder.build().expect("REF fixture");

    let ofs_oid = ofs_fixture.oid(ofs_target);
    let ref_oid = ref_fixture.oid(ref_target);
    assert_eq!(ofs_oid, ref_oid, "same content must produce same OID");

    let ofs_resolved = resolve_via_pack_io(&ofs_fixture, &ofs_oid);
    let ref_resolved = resolve_via_pack_io(&ref_fixture, &ref_oid);

    assert_eq!(ofs_resolved.0, ObjectKind::Blob);
    assert_eq!(ref_resolved.0, ObjectKind::Blob);
    assert_eq!(
        ofs_resolved.1, ref_resolved.1,
        "OFS and REF delta must resolve to identical bytes"
    );
    assert_eq!(ofs_resolved.1, b"delta-encoding-ofs");
}

/// Verifies that delta resolution produces identical bytes regardless of
/// the base object's kind.
///
/// The pack delta format is kind-agnostic: the base kind propagates to the
/// result, but the delta application engine processes copy/add instructions
/// identically for blobs, commits, trees, and tags. This test stores the
/// same byte content as both a blob and a commit, applies the same delta
/// to each, and asserts the resolved bytes match while the returned kinds
/// differ.
#[test]
fn object_kind_equivalence() {
    let content = b"kind-invariant-base-data";

    let mut builder = MultiPackFixture::builder();
    let pack = builder.add_pack(b"pack-kind");
    let blob_base = builder.add_object(pack, ObjectKind::Blob, content);
    let commit_base = builder.add_object(pack, ObjectKind::Commit, content);
    let blob_delta = builder.add_ofs_delta_mixed(pack, blob_base, 14, b"-resolved");
    let commit_delta = builder.add_ofs_delta_mixed(pack, commit_base, 14, b"-resolved");
    let fixture = builder.build().expect("kind fixture");

    let blob_oid = fixture.oid(blob_delta);
    let commit_oid = fixture.oid(commit_delta);
    assert_ne!(
        blob_oid, commit_oid,
        "different kinds produce different OIDs for the same content"
    );

    let blob_resolved = resolve_via_pack_io(&fixture, &blob_oid);
    let commit_resolved = resolve_via_pack_io(&fixture, &commit_oid);

    assert_eq!(blob_resolved.0, ObjectKind::Blob);
    assert_eq!(commit_resolved.0, ObjectKind::Commit);
    assert_eq!(
        blob_resolved.1, commit_resolved.1,
        "delta resolution must be kind-agnostic: same bytes regardless of base kind"
    );
    assert_eq!(blob_resolved.1, b"kind-invariant-resolved");
}
