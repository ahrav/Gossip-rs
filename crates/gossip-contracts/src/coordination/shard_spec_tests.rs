use rstest::rstest;

use super::*;
use crate::test_util::{
    arb_bounded_shard_spec, arb_bounded_shard_spec_with_metadata, arb_shard_spec, canonical_digest,
};
use proptest::prelude::*;

// -------------------------------------------------------------------
// CursorSemantics
// -------------------------------------------------------------------

#[test]
fn from_u8_roundtrip() {
    assert_eq!(
        CursorSemantics::from_u8(0),
        Some(CursorSemantics::Completed)
    );
    assert_eq!(
        CursorSemantics::from_u8(1),
        Some(CursorSemantics::Dispatched)
    );
    assert_eq!(CursorSemantics::from_u8(2), None);
}

#[test]
fn as_u8_stability() {
    assert_eq!(CursorSemantics::Completed.as_u8(), 0);
    assert_eq!(CursorSemantics::Dispatched.as_u8(), 1);
}

#[test]
fn canonical_bytes_discriminant_distinct() {
    let d_completed = canonical_digest(&CursorSemantics::Completed);
    let d_dispatched = canonical_digest(&CursorSemantics::Dispatched);
    assert_ne!(d_completed, d_dispatched);
}

// -------------------------------------------------------------------
// ShardSpec construction
// -------------------------------------------------------------------

#[rstest]
#[case::unbounded(ShardSpec::unbounded(), b"" as &[u8], b"" as &[u8], true, true, true)]
#[case::bounded_a_m(ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()), b"a", b"m", false, false, false)]
#[case::start_unbounded(ShardSpec::with_range(vec![], b"m".to_vec()), b"", b"m", true, false, false)]
#[case::end_unbounded(ShardSpec::with_range(b"m".to_vec(), vec![]), b"m", b"", false, true, false)]
fn shard_spec_construction_truth_table(
    #[case] spec: ShardSpec,
    #[case] exp_start: &[u8],
    #[case] exp_end: &[u8],
    #[case] start_ub: bool,
    #[case] end_ub: bool,
    #[case] full_ub: bool,
) {
    assert_eq!(spec.key_range_start(), exp_start);
    assert_eq!(spec.key_range_end(), exp_end);
    assert_eq!(spec.is_start_unbounded(), start_ub);
    assert_eq!(spec.is_end_unbounded(), end_ub);
    assert_eq!(spec.is_unbounded(), full_ub);
}

#[test]
fn shard_spec_unbounded_has_empty_metadata() {
    assert!(ShardSpec::unbounded().metadata().is_empty());
}

#[test]
#[should_panic(expected = "start must be strictly less than end")]
fn shard_spec_inverted_panics() {
    let _ = ShardSpec::with_range(b"z".to_vec(), b"a".to_vec());
}

#[test]
#[should_panic(expected = "start must be strictly less than end")]
fn shard_spec_equal_bounds_panics() {
    let _ = ShardSpec::with_range(b"a".to_vec(), b"a".to_vec());
}

#[test]
#[should_panic(expected = "key too large")]
fn with_range_panics_on_oversized_start_key() {
    let _ = ShardSpec::with_range(vec![0x01; MAX_KEY_SIZE + 1], vec![]);
}

#[test]
#[should_panic(expected = "key too large")]
fn with_range_panics_on_oversized_end_key() {
    let _ = ShardSpec::with_range(vec![], vec![0xFF; MAX_KEY_SIZE + 1]);
}

#[test]
#[should_panic(expected = "metadata too large")]
fn with_range_and_metadata_panics_on_oversized_metadata() {
    let _ = ShardSpec::with_range_and_metadata(
        b"a".to_vec(),
        b"z".to_vec(),
        vec![0xAA; MAX_METADATA_SIZE + 1],
    );
}

// -------------------------------------------------------------------
// Fallible constructors
// -------------------------------------------------------------------

#[test]
fn try_with_range_inverted() {
    let err = ShardSpec::try_with_range(b"z".to_vec(), b"a".to_vec()).unwrap_err();
    assert_eq!(
        err,
        ShardSpecInputError::InvertedRange {
            start_len: 1,
            end_len: 1,
        }
    );
}

#[test]
fn try_with_range_equal_bounds() {
    let err = ShardSpec::try_with_range(b"a".to_vec(), b"a".to_vec()).unwrap_err();
    assert!(matches!(err, ShardSpecInputError::InvertedRange { .. }));
}

#[test]
fn try_with_range_and_metadata_valid() {
    let spec =
        ShardSpec::try_with_range_and_metadata(b"a".to_vec(), b"z".to_vec(), b"meta".to_vec())
            .unwrap();
    assert_eq!(spec.key_range_start(), b"a");
    assert_eq!(spec.key_range_end(), b"z");
    assert_eq!(spec.metadata(), b"meta");
}

#[rstest]
#[case::inverted_range(
    ShardSpecInputError::InvertedRange { start_len: 3, end_len: 1 },
    "start must be strictly less than end", "3 bytes", "1 bytes",
)]
#[case::key_too_large(
    ShardSpecInputError::KeyTooLarge { size: 5000, max: 4096 },
    "5000", "4096", "",
)]
#[case::metadata_too_large(
    ShardSpecInputError::MetadataTooLarge { size: 20000, max: 16384 },
    "20000", "16384", "",
)]
fn shard_spec_input_error_display(
    #[case] err: ShardSpecInputError,
    #[case] expected1: &str,
    #[case] expected2: &str,
    #[case] expected3: &str,
) {
    let msg = err.to_string();
    assert!(msg.contains(expected1), "expected '{expected1}' in '{msg}'");
    assert!(msg.contains(expected2), "expected '{expected2}' in '{msg}'");
    if !expected3.is_empty() {
        assert!(msg.contains(expected3), "expected '{expected3}' in '{msg}'");
    }
}

// -------------------------------------------------------------------
// Size-limit validation
// -------------------------------------------------------------------

#[test]
fn try_with_range_start_key_at_max() {
    let start = vec![0x01; MAX_KEY_SIZE];
    // Use an unbounded end so it doesn't also exceed MAX_KEY_SIZE.
    let spec = ShardSpec::try_with_range(start, vec![]).unwrap();
    assert_eq!(spec.key_range_start().len(), MAX_KEY_SIZE);
}

#[test]
fn try_with_range_start_key_over_max() {
    let start = vec![0x01; MAX_KEY_SIZE + 1];
    let mut end = start.clone();
    end.push(0xFF);
    let err = ShardSpec::try_with_range(start, end).unwrap_err();
    assert_eq!(
        err,
        ShardSpecInputError::KeyTooLarge {
            size: MAX_KEY_SIZE + 1,
            max: MAX_KEY_SIZE,
        }
    );
}

#[test]
fn try_with_range_end_key_over_max() {
    let end = vec![0xFF; MAX_KEY_SIZE + 1];
    let err = ShardSpec::try_with_range(b"a".to_vec(), end).unwrap_err();
    assert!(matches!(err, ShardSpecInputError::KeyTooLarge { .. }));
}

#[test]
fn try_with_range_and_metadata_at_max() {
    let meta = vec![0xAA; MAX_METADATA_SIZE];
    let spec = ShardSpec::try_with_range_and_metadata(b"a".to_vec(), b"z".to_vec(), meta).unwrap();
    assert_eq!(spec.metadata().len(), MAX_METADATA_SIZE);
}

#[test]
fn try_with_range_and_metadata_over_max() {
    let meta = vec![0xAA; MAX_METADATA_SIZE + 1];
    let err =
        ShardSpec::try_with_range_and_metadata(b"a".to_vec(), b"z".to_vec(), meta).unwrap_err();
    assert_eq!(
        err,
        ShardSpecInputError::MetadataTooLarge {
            size: MAX_METADATA_SIZE + 1,
            max: MAX_METADATA_SIZE,
        }
    );
}

// -------------------------------------------------------------------
// Split validation
// -------------------------------------------------------------------

#[test]
fn split_valid_two_way() {
    let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    let c1 = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let c2 = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    assert!(validate_split_coverage(&parent, &[&c1, &c2]).is_ok());
}

#[test]
fn split_valid_unbounded_parent() {
    let parent = ShardSpec::unbounded();
    let c1 = ShardSpec::with_range(vec![], b"m".to_vec());
    let c2 = ShardSpec::with_range(b"m".to_vec(), vec![]);
    assert!(validate_split_coverage(&parent, &[&c1, &c2]).is_ok());
}

#[test]
fn split_no_children() {
    let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    let empty: &[&ShardSpec] = &[];
    let result = validate_split_coverage(&parent, empty);
    assert!(matches!(result, Err(SplitValidationError::NoChildren)));
}

#[test]
fn split_single_child() {
    let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    let c1 = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    let result = validate_split_coverage(&parent, &[&c1]);
    assert!(matches!(result, Err(SplitValidationError::SingleChild)));
}

#[test]
fn split_start_mismatch() {
    let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    let c1 = ShardSpec::with_range(b"b".to_vec(), b"m".to_vec());
    let c2 = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let result = validate_split_coverage(&parent, &[&c1, &c2]);
    assert!(matches!(
        result,
        Err(SplitValidationError::StartMismatch { .. })
    ));
}

#[test]
fn split_end_mismatch() {
    let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    let c1 = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let c2 = ShardSpec::with_range(b"m".to_vec(), b"y".to_vec());
    let result = validate_split_coverage(&parent, &[&c1, &c2]);
    assert!(matches!(
        result,
        Err(SplitValidationError::EndMismatch { .. })
    ));
}

#[test]
fn split_boundary_mismatch_between_children() {
    let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    let c1 = ShardSpec::with_range(b"a".to_vec(), b"g".to_vec());
    let c2 = ShardSpec::with_range(b"h".to_vec(), b"z".to_vec());
    let result = validate_split_coverage(&parent, &[&c1, &c2]);
    assert!(matches!(
        result,
        Err(SplitValidationError::BoundaryMismatch { .. })
    ));
}

#[test]
fn split_children_out_of_order_still_valid() {
    let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    // Provide children in reverse order; sorting makes it pass.
    let c1 = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let c2 = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    assert!(validate_split_coverage(&parent, &[&c1, &c2]).is_ok());
}

#[test]
fn split_inverted_child() {
    let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    // A zero-width child [m, m) passes contiguity but fails
    // the well-formedness check (start >= end).
    let c1 = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let c2 =
        ShardSpec::from_raw_parts(b"m".as_slice().into(), b"m".as_slice().into(), Box::new([]));
    let c3 = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let result = validate_split_coverage(&parent, &[&c1, &c2, &c3]);
    assert!(matches!(
        result,
        Err(SplitValidationError::InvertedChild { .. })
    ));
}

#[test]
fn split_boundary_mismatch_reports_original_indices() {
    let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    // Pass children in reverse order: index 0 is [m,z), index 1 is [a,g).
    // After sorting: [a,g) then [m,z) — gap between them.
    // The gap is between sorted[0]=original[1] and sorted[1]=original[0].
    let c0 = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let c1 = ShardSpec::with_range(b"a".to_vec(), b"g".to_vec());
    let result = validate_split_coverage(&parent, &[&c0, &c1]);
    match result {
        Err(SplitValidationError::BoundaryMismatch {
            child_index,
            next_child_index,
            ..
        }) => {
            // Original index of [a,g) is 1, original index of [m,z) is 0.
            assert_eq!(child_index, 1, "gap child should be original index 1");
            assert_eq!(next_child_index, 0, "next child should be original index 0");
        }
        other => panic!("expected BoundaryMismatch, got {other:?}"),
    }
}

#[test]
fn split_inverted_child_reports_original_index() {
    let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    // Degenerate [g,g) at original index 0, normal children at 1 and 2.
    // Stable sort on start key produces:
    //   sorted[0] = (orig 2, [a,g))
    //   sorted[1] = (orig 0, [g,g))   ← degenerate, at sorted position 1
    //   sorted[2] = (orig 1, [g,z))
    // The inverted child is at sorted position 1 but original index 0.
    let c0 =
        ShardSpec::from_raw_parts(b"g".as_slice().into(), b"g".as_slice().into(), Box::new([]));
    let c1 = ShardSpec::with_range(b"g".to_vec(), b"z".to_vec());
    let c2 = ShardSpec::with_range(b"a".to_vec(), b"g".to_vec());
    let result = validate_split_coverage(&parent, &[&c0, &c1, &c2]);
    match result {
        Err(SplitValidationError::InvertedChild { child_index }) => {
            assert_eq!(child_index, 0, "inverted child should be original index 0");
        }
        other => panic!("expected InvertedChild, got {other:?}"),
    }
}

// -------------------------------------------------------------------
// Residual split
// -------------------------------------------------------------------

#[test]
fn residual_split_valid() {
    let old_parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    let new_parent = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let residual = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    assert!(validate_residual_split(&old_parent, &new_parent, &residual).is_ok());
}

#[test]
fn residual_split_gap() {
    let old_parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    let new_parent = ShardSpec::with_range(b"a".to_vec(), b"g".to_vec());
    let residual = ShardSpec::with_range(b"h".to_vec(), b"z".to_vec());
    let result = validate_residual_split(&old_parent, &new_parent, &residual);
    assert!(result.is_err());
}

#[test]
fn residual_split_swapped_roles_rejected() {
    let old_parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    // Swap: new_parent gets upper range, residual gets lower.
    let new_parent = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let residual = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let result = validate_residual_split(&old_parent, &new_parent, &residual);
    assert!(
        matches!(result, Err(SplitValidationError::StartMismatch { .. })),
        "swapped residual split should be rejected: {result:?}"
    );
}

#[test]
fn split_two_unbounded_children_rejected() {
    let parent = ShardSpec::unbounded();
    let c1 = ShardSpec::unbounded();
    let c2 = ShardSpec::unbounded();
    let result = validate_split_coverage(&parent, &[&c1, &c2]);
    assert!(
        matches!(result, Err(SplitValidationError::OverlappingChild { .. })),
        "two fully-unbounded children should be rejected: {result:?}"
    );
}

#[test]
fn split_non_last_child_unbounded_end_rejected() {
    let parent = ShardSpec::unbounded();
    // First child covers everything, second is also unbounded.
    let c1 = ShardSpec::with_range(vec![], vec![]);
    let c2 = ShardSpec::with_range(vec![], vec![]);
    let result = validate_split_coverage(&parent, &[&c1, &c2]);
    assert!(result.is_err());
}

// -------------------------------------------------------------------
// SplitValidationError Display
// -------------------------------------------------------------------

#[test]
fn split_validation_error_display() {
    let err = SplitValidationError::BoundaryMismatch {
        child_index: 0,
        next_child_index: 1,
        child_end: b"g".as_slice().into(),
        next_child_start: b"h".as_slice().into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("boundary mismatch"));
    assert!(msg.contains("child 0"));
    assert!(msg.contains("child 1"));
}

// -------------------------------------------------------------------
// Metadata participates in canonical hashing
// -------------------------------------------------------------------

#[test]
fn with_range_and_metadata_stores_and_hashes_metadata() {
    let spec_no_meta = ShardSpec::with_range_and_metadata(b"a".to_vec(), b"z".to_vec(), vec![]);
    let spec_with_meta =
        ShardSpec::with_range_and_metadata(b"a".to_vec(), b"z".to_vec(), b"repo:org/foo".to_vec());

    // Metadata is stored.
    assert_eq!(spec_with_meta.metadata(), b"repo:org/foo");

    // Same range, different metadata → different canonical digest.
    assert_ne!(
        canonical_digest(&spec_no_meta),
        canonical_digest(&spec_with_meta),
    );
}

// -------------------------------------------------------------------
// Property-based tests
// -------------------------------------------------------------------

/// Generate a valid parent + 2–4 contiguous children via suffix
/// accumulation (same proven pattern as `arb_bounded_shard_spec`).
fn arb_valid_n_way_split() -> impl Strategy<Value = (ShardSpec, Vec<ShardSpec>)> {
    (
        proptest::collection::vec(any::<u8>(), 1..16),
        proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..8), 2..=4),
    )
        .prop_map(|(base, suffixes)| {
            let mut boundaries = vec![base.clone()];
            let mut current = base;
            for suffix in &suffixes {
                current.extend_from_slice(suffix);
                boundaries.push(current.clone());
            }
            let parent =
                ShardSpec::with_range(boundaries[0].clone(), boundaries.last().unwrap().clone());
            let children: Vec<ShardSpec> = boundaries
                .windows(2)
                .map(|w| ShardSpec::with_range(w[0].clone(), w[1].clone()))
                .collect();
            (parent, children)
        })
}

proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    // -- Stability: same input → same digest ----------------------------

    #[test]
    fn shard_spec_canonical_bytes_stable(
        start in proptest::collection::vec(any::<u8>(), 1..64),
        suffix in proptest::collection::vec(any::<u8>(), 1..8),
    ) {
        let mut end = start.clone();
        end.extend_from_slice(&suffix);
        let spec = ShardSpec::with_range(start, end);
        prop_assert_eq!(canonical_digest(&spec), canonical_digest(&spec));
    }

    // -- Collision-freedom: distinct specs → distinct digests -----------

    #[test]
    fn shard_spec_canonical_bytes_collision_free(
        a in arb_bounded_shard_spec(),
        b in arb_bounded_shard_spec(),
    ) {
        prop_assume!(a != b);
        prop_assert_ne!(canonical_digest(&a), canonical_digest(&b));
    }

    // -- contains_key equivalence with manual check ---------------------

    #[test]
    fn contains_key_matches_manual_check(
        spec in arb_shard_spec(),
        key in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let above_start = spec.is_start_unbounded()
            || key.as_slice() >= spec.key_range_start();
        let below_end = spec.is_end_unbounded()
            || key.as_slice() < spec.key_range_end();
        let expected = above_start && below_end;
        prop_assert_eq!(spec.contains_key(&key), expected);
    }

    // -- split coverage: key in parent iff in exactly one child ----------

    #[test]
    fn split_coverage_roundtrip(
        (parent, children) in arb_valid_n_way_split(),
        key in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let refs: Vec<&ShardSpec> = children.iter().collect();
        prop_assert!(validate_split_coverage(&parent, &refs).is_ok());
        let parent_has = parent.contains_key(&key);
        let child_count = children.iter().filter(|c| c.contains_key(&key)).count();
        if parent_has {
            prop_assert_eq!(child_count, 1,
                "key in parent but in {} children", child_count);
        } else {
            prop_assert_eq!(child_count, 0,
                "key outside parent but in {} children", child_count);
        }
    }

    // -- residual split: old_parent == new_parent ∪ residual -------------

    #[test]
    fn residual_split_roundtrip(
        start in proptest::collection::vec(any::<u8>(), 1..16),
        mid_suffix in proptest::collection::vec(any::<u8>(), 1..8),
        end_suffix in proptest::collection::vec(any::<u8>(), 1..8),
        key in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut mid = start.clone();
        mid.extend_from_slice(&mid_suffix);
        let mut end = mid.clone();
        end.extend_from_slice(&end_suffix);

        let old_parent = ShardSpec::with_range(start.clone(), end.clone());
        let new_parent = ShardSpec::with_range(start, mid.clone());
        let residual = ShardSpec::with_range(mid, end);

        prop_assert!(validate_residual_split(&old_parent, &new_parent, &residual).is_ok());

        let in_old = old_parent.contains_key(&key);
        let in_new = new_parent.contains_key(&key);
        let in_res = residual.contains_key(&key);
        prop_assert_eq!(in_old, in_new || in_res);
        prop_assert!(!(in_new && in_res), "key in both new_parent and residual");
    }

    // -- Constructor equivalence: try_with_range ≡ with_range ------------

    #[test]
    fn try_with_range_equivalent_to_with_range(
        spec in arb_shard_spec(),
    ) {
        let start = spec.key_range_start().to_vec();
        let end = spec.key_range_end().to_vec();
        let expected = ShardSpec::with_range(start.clone(), end.clone());
        let result = ShardSpec::try_with_range(start, end);
        prop_assert_eq!(result, Ok(expected));
    }

    // -- Constructor equivalence: try_with_range_and_metadata -------------

    #[test]
    fn try_with_range_and_metadata_equivalent(
        start in proptest::collection::vec(any::<u8>(), 1..64),
        suffix in proptest::collection::vec(any::<u8>(), 1..8),
        metadata in proptest::collection::vec(any::<u8>(), 0..32),
    ) {
        let mut end = start.clone();
        end.extend_from_slice(&suffix);
        let try_result = ShardSpec::try_with_range_and_metadata(
            start.clone(), end.clone(), metadata.clone(),
        );
        let direct = ShardSpec::with_range_and_metadata(start, end, metadata);
        prop_assert_eq!(try_result, Ok(direct));
    }

    // -- Canonical hash consistency: ShardSpec and ShardSpecRef produce
    //    the same digest for the same logical value.

    #[test]
    fn shard_spec_and_ref_canonical_hash_consistent(
        spec in arb_shard_spec(),
    ) {
        let owned_digest = canonical_digest(&spec);
        let ref_digest = canonical_digest(&spec.as_ref());
        prop_assert_eq!(
            owned_digest, ref_digest,
            "ShardSpec and ShardSpecRef must produce identical canonical digests"
        );
    }

    // -- Round-trip: try_from_ref(spec.as_ref()) recovers the original.

    #[test]
    fn try_from_ref_round_trip(
        spec in arb_shard_spec(),
    ) {
        let reconstructed = ShardSpec::try_from_ref(spec.as_ref()).unwrap();
        prop_assert_eq!(
            spec, reconstructed,
            "ShardSpec::try_from_ref must round-trip through as_ref"
        );
    }

    // -- Metadata distinction: different metadata → different digest -----

    #[test]
    fn metadata_changes_canonical_digest(
        spec in arb_bounded_shard_spec_with_metadata(),
    ) {
        let no_meta = ShardSpec::with_range(
            spec.key_range_start().to_vec(),
            spec.key_range_end().to_vec(),
        );
        // If the spec has non-empty metadata, digests must differ.
        if !spec.metadata().is_empty() {
            prop_assert_ne!(
                canonical_digest(&spec),
                canonical_digest(&no_meta),
                "non-empty metadata must change the canonical digest"
            );
        }
    }
}

// -------------------------------------------------------------------
// Split coverage rejects oversized child specs
// -------------------------------------------------------------------

// -------------------------------------------------------------------
// ShardArena
// -------------------------------------------------------------------

/// Helper: create a small arena suitable for unit tests.
fn test_arena(slots: usize, bytes: usize) -> ShardArena {
    ShardArena::with_capacity(slots, bytes)
}

#[test]
fn arena_basic_alloc_view_free_cycle() {
    let mut arena = test_arena(4, 4096);
    let spec = ShardSpecRef::new(b"a", b"z", b"meta");
    let handle = arena.alloc_spec(spec).unwrap();
    let view = arena.view_spec(&handle);
    assert_eq!(view.key_range_start(), b"a");
    assert_eq!(view.key_range_end(), b"z");
    assert_eq!(view.metadata(), b"meta");
    arena.free_spec(handle);
}

#[test]
fn arena_slot_exhaustion_returns_slab_full() {
    let mut arena = test_arena(2, 4096);
    let spec = ShardSpecRef::new(b"a", b"z", &[]);
    let h1 = arena.alloc_spec(spec).unwrap();
    let h2 = arena.alloc_spec(spec).unwrap();
    let err = arena.alloc_spec(spec).unwrap_err();
    assert_eq!(
        err,
        SlabFull {
            requested: 1,
            available: 0
        }
    );
    // Free all specs before drop to satisfy ByteSlab leak detector.
    arena.free_spec(h1);
    arena.free_spec(h2);
}

#[test]
fn arena_byte_capacity_exhaustion_returns_slab_full() {
    // Very small byte capacity: not enough for even one spec.
    let mut arena = test_arena(4, 1);
    let spec = ShardSpecRef::new(b"a", b"z", b"metadata_payload");
    assert!(arena.alloc_spec(spec).is_err());
}

#[test]
#[should_panic(expected = "stale handle generation")]
fn arena_stale_handle_view_spec_panics() {
    let mut arena = test_arena(4, 4096);
    let spec = ShardSpecRef::new(b"a", b"z", &[]);
    let handle = arena.alloc_spec(spec).unwrap();
    arena.free_spec(handle);
    // handle is now stale (generation incremented)
    let _ = arena.view_spec(&handle);
}

#[test]
fn arena_stale_handle_free_spec_is_silent() {
    let mut arena = test_arena(4, 4096);
    let spec = ShardSpecRef::new(b"a", b"z", &[]);
    let handle = arena.alloc_spec(spec).unwrap();
    arena.free_spec(handle);
    // Double-free with stale handle should be silently ignored.
    arena.free_spec(handle);
}

#[test]
fn arena_slot_reuse_after_free() {
    let mut arena = test_arena(1, 4096);
    let spec1 = ShardSpecRef::new(b"a", b"m", &[]);
    let h1 = arena.alloc_spec(spec1).unwrap();
    arena.free_spec(h1);

    // The single slot is free again — a new alloc should succeed.
    let spec2 = ShardSpecRef::new(b"m", b"z", b"different");
    let h2 = arena.alloc_spec(spec2).unwrap();
    let view = arena.view_spec(&h2);
    assert_eq!(view.key_range_start(), b"m");
    assert_eq!(view.key_range_end(), b"z");
    assert_eq!(view.metadata(), b"different");
    arena.free_spec(h2);
}

#[test]
#[should_panic(expected = "invalid slot")]
fn arena_invalid_slot_index_panics() {
    let arena = test_arena(2, 4096);
    let bogus = ShardSpecHandle {
        slot: 999,
        generation: 0,
    };
    let _ = arena.view_spec(&bogus);
}

#[test]
fn arena_rollback_on_slab_byte_exhaustion() {
    // 2 slots, but only enough bytes for one spec.
    let mut arena = test_arena(2, 64);
    let small = ShardSpecRef::new(b"a", b"b", &[]);
    let h1 = arena.alloc_spec(small).unwrap();

    // Second alloc exceeds byte capacity — should fail and
    // return the slot to the free list.
    let large = ShardSpecRef::new(b"a", b"z", &[0xAA; 200]);
    assert!(arena.alloc_spec(large).is_err());

    // The slot should have been returned, so a small alloc succeeds.
    let h2 = arena.alloc_spec(small).unwrap();

    // Free all specs before drop to satisfy ByteSlab leak detector.
    arena.free_spec(h1);
    arena.free_spec(h2);
}

// -------------------------------------------------------------------
// validate_ref error paths
// -------------------------------------------------------------------

#[rstest]
#[case::oversized_start_key(
    vec![0x01; MAX_KEY_SIZE + 1], b"z".to_vec(), vec![],
    ShardSpecInputError::KeyTooLarge { size: MAX_KEY_SIZE + 1, max: MAX_KEY_SIZE },
)]
#[case::oversized_end_key(
    b"a".to_vec(), vec![0xFF; MAX_KEY_SIZE + 1], vec![],
    ShardSpecInputError::KeyTooLarge { size: MAX_KEY_SIZE + 1, max: MAX_KEY_SIZE },
)]
#[case::oversized_metadata(
    b"a".to_vec(), b"z".to_vec(), vec![0xAA; MAX_METADATA_SIZE + 1],
    ShardSpecInputError::MetadataTooLarge { size: MAX_METADATA_SIZE + 1, max: MAX_METADATA_SIZE },
)]
#[case::inverted_range(
    b"z".to_vec(), b"a".to_vec(), vec![],
    ShardSpecInputError::InvertedRange { start_len: 1, end_len: 1 },
)]
fn validate_ref_rejects_invalid_spec(
    #[case] start: Vec<u8>,
    #[case] end: Vec<u8>,
    #[case] metadata: Vec<u8>,
    #[case] expected: ShardSpecInputError,
) {
    let spec = ShardSpecRef::new(&start, &end, &metadata);
    let err = ShardSpec::validate_ref(spec).unwrap_err();
    assert_eq!(err, expected);
}

#[test]
fn validate_ref_accepts_valid_spec() {
    let spec = ShardSpecRef::new(b"a", b"z", b"meta");
    assert!(ShardSpec::validate_ref(spec).is_ok());
}

// -------------------------------------------------------------------
// Split coverage rejects oversized child specs
// -------------------------------------------------------------------

#[test]
fn split_coverage_rejects_child_with_oversized_metadata() {
    // Children with valid key ranges but oversized metadata should be
    // rejected by split coverage validation to prevent downstream
    // panics in AcquireScratch::write_spec.
    let oversized_meta = vec![0xAA; MAX_METADATA_SIZE + 1];
    let child1 = ShardSpecRef::new(b"a", b"m", &oversized_meta);
    let child2 = ShardSpecRef::new(b"m", b"z", &[]);
    let result = validate_split_coverage_bounds(b"a", b"z", &[child1, child2]);
    assert!(
        result.is_err(),
        "validate_split_coverage_bounds should reject children with metadata \
         exceeding MAX_METADATA_SIZE",
    );
}
