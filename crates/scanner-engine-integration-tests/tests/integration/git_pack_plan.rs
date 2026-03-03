//! Integration tests for pack planning against synthetic pack bytes.
//!
//! These tests construct minimal PACK buffers with explicit delta chains so
//! the pack planner can be validated without relying on real repositories.
//! The PACK trailers are dummy-sized (OID length only); checksums are not
//! verified by the planner.

use std::collections::HashMap;

use scanner_git::{
    BaseLoc, ByteRef, CandidateContext, ChangeKind, DeltaKind, OidBytes, PackCandidate,
    PackPlanConfig, PackPlanError, PackView, build_pack_plans,
};
use scanner_git::{OidResolver, PackPlan};

struct NoopResolver;

impl OidResolver for NoopResolver {
    fn resolve(&self, _oid: &OidBytes) -> Result<Option<(u16, u64)>, PackPlanError> {
        Ok(None)
    }
}

struct TestResolver {
    map: HashMap<OidBytes, (u16, u64)>,
}

impl OidResolver for TestResolver {
    fn resolve(&self, oid: &OidBytes) -> Result<Option<(u16, u64)>, PackPlanError> {
        Ok(self.map.get(oid).copied())
    }
}

fn ctx() -> CandidateContext {
    CandidateContext {
        commit_id: 1,
        parent_idx: 0,
        change_kind: ChangeKind::Add,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref: ByteRef::new(0, 0),
    }
}

/// Encodes a minimal pack object header for the given type/size.
fn encode_obj_header(obj_type: u8, mut size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = ((obj_type & 0x07) << 4) | ((size & 0x0f) as u8);
    size >>= 4;
    if size != 0 {
        first |= 0x80;
    }
    out.push(first);
    while size != 0 {
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

/// Encodes an OFS_DELTA base distance using Git's pack format.
fn encode_ofs_distance(mut dist: u64) -> Vec<u8> {
    assert!(dist > 0);
    let mut bytes = Vec::new();
    bytes.push((dist & 0x7f) as u8);
    dist >>= 7;
    while dist > 0 {
        dist -= 1;
        bytes.push(((dist & 0x7f) as u8) | 0x80);
        dist >>= 7;
    }
    bytes.reverse();
    bytes
}

/// Builds a minimal PACK buffer with room for the trailing checksum bytes.
fn build_pack(oid_len: usize, entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut max_end = 12u64;
    for (offset, bytes) in entries {
        let end = offset + bytes.len() as u64;
        if end > max_end {
            max_end = end;
        }
    }
    let total_len = max_end as usize + oid_len;
    let mut buf = vec![0u8; total_len];
    buf[0..4].copy_from_slice(b"PACK");
    buf[4..8].copy_from_slice(&2u32.to_be_bytes());
    buf[8..12].copy_from_slice(&(entries.len() as u32).to_be_bytes());
    for (offset, bytes) in entries {
        let start = *offset as usize;
        buf[start..start + bytes.len()].copy_from_slice(bytes);
    }
    buf
}

fn unpack_plan(plans: Vec<PackPlan>) -> PackPlan {
    assert_eq!(plans.len(), 1);
    plans.into_iter().next().unwrap()
}

#[test]
fn ofs_delta_chain_includes_base_closure() {
    let base_offset = 12u64;
    let delta1_offset = 32u64;
    let delta2_offset = 52u64;

    let base_header = encode_obj_header(3, 1);
    let mut delta1_header = encode_obj_header(6, 1);
    delta1_header.extend_from_slice(&encode_ofs_distance(delta1_offset - base_offset));
    let mut delta2_header = encode_obj_header(6, 1);
    delta2_header.extend_from_slice(&encode_ofs_distance(delta2_offset - delta1_offset));

    let pack_bytes = build_pack(
        20,
        &[
            (base_offset, base_header),
            (delta1_offset, delta1_header),
            (delta2_offset, delta2_header),
        ],
    );
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let cand = PackCandidate {
        oid: OidBytes::sha1([0x11; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: delta2_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 2,
        ..Default::default()
    };

    let plan = unpack_plan(
        build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap(),
    );
    assert_eq!(
        plan.need_offsets(),
        vec![base_offset, delta1_offset, delta2_offset]
    );
}

#[test]
fn ofs_delta_chain_respects_depth_limit() {
    let base_offset = 12u64;
    let delta1_offset = 32u64;
    let delta2_offset = 52u64;

    let base_header = encode_obj_header(3, 1);
    let mut delta1_header = encode_obj_header(6, 1);
    delta1_header.extend_from_slice(&encode_ofs_distance(delta1_offset - base_offset));
    let mut delta2_header = encode_obj_header(6, 1);
    delta2_header.extend_from_slice(&encode_ofs_distance(delta2_offset - delta1_offset));

    let pack_bytes = build_pack(
        20,
        &[
            (base_offset, base_header),
            (delta1_offset, delta1_header),
            (delta2_offset, delta2_header),
        ],
    );
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let cand = PackCandidate {
        oid: OidBytes::sha1([0xaa; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: delta2_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 1,
        ..Default::default()
    };

    let plan = unpack_plan(
        build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap(),
    );
    assert_eq!(plan.need_offsets(), vec![delta1_offset, delta2_offset]);
}

#[test]
fn worklist_limit_exceeded_on_delta_expansion() {
    let base_offset = 12u64;
    let delta_offset = 32u64;

    let base_header = encode_obj_header(3, 1);
    let mut delta_header = encode_obj_header(6, 1);
    delta_header.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));

    let pack_bytes = build_pack(
        20,
        &[(base_offset, base_header), (delta_offset, delta_header)],
    );
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let cand = PackCandidate {
        oid: OidBytes::sha1([0xbb; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: delta_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 1,
        max_worklist_entries: 1,
        ..Default::default()
    };

    let err = build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap_err();
    assert!(matches!(
        err,
        PackPlanError::WorklistLimitExceeded {
            limit: 1,
            observed: 2
        }
    ));
}

#[test]
fn ref_delta_inside_pack_is_resolved() {
    let base_offset = 12u64;
    let ref_offset = 40u64;
    let base_oid = OidBytes::sha1([0x22; 20]);

    let base_header = encode_obj_header(3, 1);
    let mut ref_header = encode_obj_header(7, 1);
    ref_header.extend_from_slice(base_oid.as_slice());

    let pack_bytes = build_pack(20, &[(base_offset, base_header), (ref_offset, ref_header)]);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let mut map = HashMap::new();
    map.insert(base_oid, (0u16, base_offset));
    let resolver = TestResolver { map };

    let cand = PackCandidate {
        oid: OidBytes::sha1([0x33; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: ref_offset,
    };

    let plan = unpack_plan(
        build_pack_plans(
            vec![cand],
            &[Some(pack_view)],
            &resolver,
            &PackPlanConfig::default(),
        )
        .unwrap(),
    );
    assert_eq!(plan.need_offsets(), vec![base_offset, ref_offset]);

    let dep = plan
        .delta_deps()
        .iter()
        .find(|dep| dep.offset == ref_offset)
        .expect("ref dep");
    assert_eq!(dep.kind, DeltaKind::Ref);
    assert!(matches!(dep.base, BaseLoc::Offset(o) if o == base_offset));
}

#[test]
fn ref_delta_outside_pack_is_external() {
    let base_offset = 12u64;
    let ref_offset = 40u64;
    let base_oid = OidBytes::sha1([0x44; 20]);

    let base_header = encode_obj_header(3, 1);
    let mut ref_header = encode_obj_header(7, 1);
    ref_header.extend_from_slice(base_oid.as_slice());

    let pack_bytes = build_pack(20, &[(base_offset, base_header), (ref_offset, ref_header)]);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let mut map = HashMap::new();
    map.insert(base_oid, (1u16, base_offset));
    let resolver = TestResolver { map };

    let cand = PackCandidate {
        oid: OidBytes::sha1([0x55; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: ref_offset,
    };

    let plan = unpack_plan(
        build_pack_plans(
            vec![cand],
            &[Some(pack_view)],
            &resolver,
            &PackPlanConfig::default(),
        )
        .unwrap(),
    );
    assert_eq!(plan.need_offsets(), vec![ref_offset]);
    assert_eq!(plan.stats().external_bases(), 1);

    let dep = plan
        .delta_deps()
        .iter()
        .find(|dep| dep.offset == ref_offset)
        .expect("ref dep");
    assert_eq!(dep.kind, DeltaKind::Ref);
    assert!(matches!(dep.base, BaseLoc::External { oid } if oid == base_oid));
}

#[test]
fn ref_delta_missing_base_is_external() {
    let base_offset = 12u64;
    let ref_offset = 40u64;
    let base_oid = OidBytes::sha1([0x66; 20]);

    let base_header = encode_obj_header(3, 1);
    let mut ref_header = encode_obj_header(7, 1);
    ref_header.extend_from_slice(base_oid.as_slice());

    let pack_bytes = build_pack(20, &[(base_offset, base_header), (ref_offset, ref_header)]);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let cand = PackCandidate {
        oid: OidBytes::sha1([0x77; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: ref_offset,
    };

    let plan = unpack_plan(
        build_pack_plans(
            vec![cand],
            &[Some(pack_view)],
            &NoopResolver,
            &PackPlanConfig::default(),
        )
        .unwrap(),
    );
    assert_eq!(plan.need_offsets(), vec![ref_offset]);
    assert_eq!(plan.stats().external_bases(), 1);

    let dep = plan
        .delta_deps()
        .iter()
        .find(|dep| dep.offset == ref_offset)
        .expect("ref dep");
    assert_eq!(dep.kind, DeltaKind::Ref);
    assert!(matches!(dep.base, BaseLoc::External { oid } if oid == base_oid));
}

#[test]
fn ref_delta_base_lookup_limit_enforced() {
    let base_offset = 12u64;
    let ref_offset = 40u64;
    let base_oid = OidBytes::sha1([0x88; 20]);

    let base_header = encode_obj_header(3, 1);
    let mut ref_header = encode_obj_header(7, 1);
    ref_header.extend_from_slice(base_oid.as_slice());

    let pack_bytes = build_pack(20, &[(base_offset, base_header), (ref_offset, ref_header)]);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let cand = PackCandidate {
        oid: OidBytes::sha1([0x99; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: ref_offset,
    };

    let config = PackPlanConfig {
        max_base_lookups: 0,
        ..Default::default()
    };

    let err = build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap_err();
    assert!(matches!(
        err,
        PackPlanError::BaseLookupLimitExceeded {
            limit: 0,
            observed: 1
        }
    ));
}

// ---------------------------------------------------------------------------
// Helper: build an N-deep OFS_DELTA chain
// ---------------------------------------------------------------------------

/// Builds entries for an N-deep OFS_DELTA chain starting at offset 12.
/// Returns `(entries, offsets)` where `offsets[0]` is the base and
/// `offsets[N]` is the deepest delta.
fn build_deep_ofs_chain(depth: usize) -> (Vec<(u64, Vec<u8>)>, Vec<u64>) {
    let mut entries = Vec::new();
    let mut offsets = Vec::new();
    let base_offset = 12u64;
    let base_header = encode_obj_header(3, 1); // blob, size=1
    offsets.push(base_offset);
    entries.push((base_offset, base_header));

    let mut current_offset = base_offset + 20; // leave room
    for i in 0..depth {
        let prev_offset = offsets[i];
        let mut header = encode_obj_header(6, 1); // OFS_DELTA, size=1
        header.extend_from_slice(&encode_ofs_distance(current_offset - prev_offset));
        offsets.push(current_offset);
        entries.push((current_offset, header));
        current_offset += 20; // leave room between entries
    }
    (entries, offsets)
}

// ---------------------------------------------------------------------------
// Task 1: Mixed OFS/REF delta chain tests
// ---------------------------------------------------------------------------

#[test]
fn mixed_ofs_ref_delta_chain_resolution() {
    // Object 0 at offset 12: Non-delta blob (type=3, size=1)
    // Object 1 at offset 32: OFS_DELTA referencing Object 0 (type=6)
    // Object 2 at offset 52: REF_DELTA referencing Object 1 via OID (type=7)
    let obj0_offset = 12u64;
    let obj1_offset = 32u64;
    let obj2_offset = 52u64;

    let obj0_header = encode_obj_header(3, 1); // blob
    let mut obj1_header = encode_obj_header(6, 1); // OFS_DELTA
    obj1_header.extend_from_slice(&encode_ofs_distance(obj1_offset - obj0_offset));

    let obj1_oid = OidBytes::sha1([0xCC; 20]);
    let mut obj2_header = encode_obj_header(7, 1); // REF_DELTA
    obj2_header.extend_from_slice(obj1_oid.as_slice());

    let pack_bytes = build_pack(
        20,
        &[
            (obj0_offset, obj0_header),
            (obj1_offset, obj1_header),
            (obj2_offset, obj2_header),
        ],
    );
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    // Resolver maps Object 1's OID to (pack_id=0, obj1_offset).
    let mut map = HashMap::new();
    map.insert(obj1_oid, (0u16, obj1_offset));
    let resolver = TestResolver { map };

    let cand = PackCandidate {
        oid: OidBytes::sha1([0xC1; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: obj2_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 4,
        ..Default::default()
    };

    let plan =
        unpack_plan(build_pack_plans(vec![cand], &[Some(pack_view)], &resolver, &config).unwrap());

    // All 3 offsets must be present.
    assert_eq!(
        plan.need_offsets(),
        vec![obj0_offset, obj1_offset, obj2_offset]
    );

    // Object 1 is an OFS_DELTA with base at Object 0.
    let dep1 = plan
        .delta_deps()
        .iter()
        .find(|dep| dep.offset == obj1_offset)
        .expect("obj1 dep");
    assert_eq!(dep1.kind, DeltaKind::Ofs);
    assert!(matches!(dep1.base, BaseLoc::Offset(o) if o == obj0_offset));

    // Object 2 is a REF_DELTA resolved to Object 1 (same pack).
    let dep2 = plan
        .delta_deps()
        .iter()
        .find(|dep| dep.offset == obj2_offset)
        .expect("obj2 dep");
    assert_eq!(dep2.kind, DeltaKind::Ref);
    assert!(matches!(dep2.base, BaseLoc::Offset(o) if o == obj1_offset));
}

#[test]
fn mixed_ref_ofs_ref_chain_resolution() {
    // Chain: base → REF_DELTA → OFS_DELTA → REF_DELTA (candidate)
    // This exercises alternating resolution modes.
    let base_offset = 12u64;
    let ref1_offset = 40u64; // REF_DELTA → base
    let ofs_offset = 80u64; // OFS_DELTA → ref1
    let ref2_offset = 120u64; // REF_DELTA → ofs (candidate)

    let base_header = encode_obj_header(3, 1); // blob

    let base_oid = OidBytes::sha1([0xDD; 20]);
    let mut ref1_header = encode_obj_header(7, 1); // REF_DELTA
    ref1_header.extend_from_slice(base_oid.as_slice());

    let mut ofs_header = encode_obj_header(6, 1); // OFS_DELTA
    ofs_header.extend_from_slice(&encode_ofs_distance(ofs_offset - ref1_offset));

    let ofs_oid = OidBytes::sha1([0xDE; 20]);
    let mut ref2_header = encode_obj_header(7, 1); // REF_DELTA
    ref2_header.extend_from_slice(ofs_oid.as_slice());

    let pack_bytes = build_pack(
        20,
        &[
            (base_offset, base_header),
            (ref1_offset, ref1_header),
            (ofs_offset, ofs_header),
            (ref2_offset, ref2_header),
        ],
    );
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let mut map = HashMap::new();
    map.insert(base_oid, (0u16, base_offset));
    map.insert(ofs_oid, (0u16, ofs_offset));
    let resolver = TestResolver { map };

    let cand = PackCandidate {
        oid: OidBytes::sha1([0xC2; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: ref2_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 8,
        ..Default::default()
    };

    let plan =
        unpack_plan(build_pack_plans(vec![cand], &[Some(pack_view)], &resolver, &config).unwrap());

    // All 4 offsets must be present.
    assert_eq!(
        plan.need_offsets(),
        vec![base_offset, ref1_offset, ofs_offset, ref2_offset]
    );

    // ref2 is REF_DELTA resolved to ofs_offset (same pack).
    let dep_ref2 = plan
        .delta_deps()
        .iter()
        .find(|dep| dep.offset == ref2_offset)
        .expect("ref2 dep");
    assert_eq!(dep_ref2.kind, DeltaKind::Ref);
    assert!(matches!(dep_ref2.base, BaseLoc::Offset(o) if o == ofs_offset));

    // ofs is OFS_DELTA referencing ref1_offset.
    let dep_ofs = plan
        .delta_deps()
        .iter()
        .find(|dep| dep.offset == ofs_offset)
        .expect("ofs dep");
    assert_eq!(dep_ofs.kind, DeltaKind::Ofs);
    assert!(matches!(dep_ofs.base, BaseLoc::Offset(o) if o == ref1_offset));

    // ref1 is REF_DELTA resolved to base_offset (same pack).
    let dep_ref1 = plan
        .delta_deps()
        .iter()
        .find(|dep| dep.offset == ref1_offset)
        .expect("ref1 dep");
    assert_eq!(dep_ref1.kind, DeltaKind::Ref);
    assert!(matches!(dep_ref1.base, BaseLoc::Offset(o) if o == base_offset));
}

#[test]
fn mixed_chain_with_external_ref() {
    // Chain: OFS_DELTA → REF_DELTA (external base in pack_id=1)
    // The OFS_DELTA's base is the REF_DELTA, which itself has an external base.
    let ref_offset = 12u64; // REF_DELTA with external base
    let ofs_offset = 60u64; // OFS_DELTA referencing ref_offset (candidate)

    let external_base_oid = OidBytes::sha1([0xEE; 20]);
    let mut ref_header = encode_obj_header(7, 1); // REF_DELTA
    ref_header.extend_from_slice(external_base_oid.as_slice());

    let mut ofs_header = encode_obj_header(6, 1); // OFS_DELTA
    ofs_header.extend_from_slice(&encode_ofs_distance(ofs_offset - ref_offset));

    let pack_bytes = build_pack(20, &[(ref_offset, ref_header), (ofs_offset, ofs_header)]);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    // External base resolves to a different pack (pack_id=1).
    let mut map = HashMap::new();
    map.insert(external_base_oid, (1u16, 100u64));
    let resolver = TestResolver { map };

    let cand = PackCandidate {
        oid: OidBytes::sha1([0xC3; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: ofs_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 4,
        ..Default::default()
    };

    let plan =
        unpack_plan(build_pack_plans(vec![cand], &[Some(pack_view)], &resolver, &config).unwrap());

    // Both local offsets must be in need_offsets.
    assert_eq!(plan.need_offsets(), vec![ref_offset, ofs_offset]);

    // The OFS_DELTA references the REF_DELTA in the same pack.
    let dep_ofs = plan
        .delta_deps()
        .iter()
        .find(|dep| dep.offset == ofs_offset)
        .expect("ofs dep");
    assert_eq!(dep_ofs.kind, DeltaKind::Ofs);
    assert!(matches!(dep_ofs.base, BaseLoc::Offset(o) if o == ref_offset));

    // The REF_DELTA's base is external (different pack).
    let dep_ref = plan
        .delta_deps()
        .iter()
        .find(|dep| dep.offset == ref_offset)
        .expect("ref dep");
    assert_eq!(dep_ref.kind, DeltaKind::Ref);
    assert!(
        matches!(dep_ref.base, BaseLoc::External { oid } if oid == external_base_oid),
        "REF_DELTA base should be external"
    );

    assert_eq!(plan.stats().external_bases(), 1);
}

// ---------------------------------------------------------------------------
// Task 2: Deep delta chain boundary tests
// ---------------------------------------------------------------------------

#[test]
fn deep_ofs_chain_at_depth_32() {
    let (entries, offsets) = build_deep_ofs_chain(32);
    assert_eq!(offsets.len(), 33); // base + 32 deltas

    let pack_bytes = build_pack(20, &entries);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let candidate_offset = *offsets.last().unwrap();
    let cand = PackCandidate {
        oid: OidBytes::sha1([0xD1; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: candidate_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 64,
        ..Default::default()
    };

    let plan = unpack_plan(
        build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap(),
    );

    assert_eq!(
        plan.need_offsets().len(),
        33,
        "base + 32 deltas = 33 offsets"
    );
    // Verify all offsets are present in sorted order.
    for &off in &offsets {
        assert!(
            plan.need_offsets().contains(&off),
            "offset {off} missing from need_offsets"
        );
    }
}

#[test]
fn deep_ofs_chain_at_exact_depth_limit() {
    // 64-deep chain: base + 64 deltas = 65 objects.
    // With max_delta_depth: 64, the candidate starts at depth 0.
    // Expansion proceeds: depth 0..63 all pass the gate (depth < 64).
    // The base is pushed at depth 64 and is a NonDelta, so no further expansion
    // is needed. All 65 offsets should be included.
    let (entries, offsets) = build_deep_ofs_chain(64);
    assert_eq!(offsets.len(), 65); // base + 64 deltas

    let pack_bytes = build_pack(20, &entries);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let candidate_offset = *offsets.last().unwrap();
    let cand = PackCandidate {
        oid: OidBytes::sha1([0xD2; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: candidate_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 64,
        ..Default::default()
    };

    let plan = unpack_plan(
        build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap(),
    );

    assert_eq!(
        plan.need_offsets().len(),
        65,
        "base + 64 deltas = 65 offsets at exact depth limit"
    );
    // The root base must be present.
    assert!(
        plan.need_offsets().contains(&offsets[0]),
        "root base must be included at exact depth limit"
    );
}

#[test]
fn deep_ofs_chain_exceeds_depth_limit() {
    // 65-deep chain: base + 65 deltas = 66 objects.
    // With max_delta_depth: 64, the candidate starts at depth 0.
    // The chain walks depths 0..63 (items at depth < 64 can expand).
    // At depth 63, the delta at offsets[2] is processed and its base offsets[1]
    // is pushed at depth 64. At depth 64, can_expand is false (64 < 64 = false),
    // so offsets[0] (the root base) is NOT pushed.
    // Result: 65 offsets (candidate + 64 ancestors), root base excluded.
    let (entries, offsets) = build_deep_ofs_chain(65);
    assert_eq!(offsets.len(), 66); // base + 65 deltas

    let pack_bytes = build_pack(20, &entries);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let candidate_offset = *offsets.last().unwrap();
    let cand = PackCandidate {
        oid: OidBytes::sha1([0xD3; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: candidate_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 64,
        ..Default::default()
    };

    let plan = unpack_plan(
        build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap(),
    );

    // The root base (offsets[0]) should NOT be in need_offsets.
    assert!(
        !plan.need_offsets().contains(&offsets[0]),
        "root base must be excluded when chain exceeds depth limit"
    );
    // We should have 65 offsets: the candidate + 64 ancestors (deltas 1..65).
    assert_eq!(
        plan.need_offsets().len(),
        65,
        "should include candidate + 64 levels of expansion, not the root base"
    );
}

#[test]
fn deep_ofs_chain_depth_128_rejected() {
    // 128-deep chain: base + 128 deltas = 129 objects.
    // With max_delta_depth: 64, expansion stops at depth 64.
    // The root base and many intermediate entries are beyond the depth window.
    let (entries, offsets) = build_deep_ofs_chain(128);
    assert_eq!(offsets.len(), 129); // base + 128 deltas

    let pack_bytes = build_pack(20, &entries);
    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();

    let candidate_offset = *offsets.last().unwrap();
    let cand = PackCandidate {
        oid: OidBytes::sha1([0xD4; 20]),
        ctx: ctx(),
        pack_id: 0,
        offset: candidate_offset,
    };

    let config = PackPlanConfig {
        max_delta_depth: 64,
        ..Default::default()
    };

    let plan = unpack_plan(
        build_pack_plans(vec![cand], &[Some(pack_view)], &NoopResolver, &config).unwrap(),
    );

    // The root base must NOT be in need_offsets.
    assert!(
        !plan.need_offsets().contains(&offsets[0]),
        "root base must not be included for 128-deep chain with limit 64"
    );

    // Expansion stops at depth 64: candidate (depth 0) + 64 levels = 65 offsets.
    assert_eq!(
        plan.need_offsets().len(),
        65,
        "expansion must stop at depth 64, yielding candidate + 64 ancestors"
    );

    // Verify that the entries beyond the depth window are excluded.
    // offsets[0..64] (the base and first 63 deltas) should NOT be present.
    for &off in &offsets[..64] {
        assert!(
            !plan.need_offsets().contains(&off),
            "offset {off} should be outside the depth window"
        );
    }

    // offsets[64..129] (the last 65 entries) SHOULD all be present.
    for &off in &offsets[64..] {
        assert!(
            plan.need_offsets().contains(&off),
            "offset {off} should be within the depth window"
        );
    }
}
