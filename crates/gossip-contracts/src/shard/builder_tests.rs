use super::{PreallocShardBuilder, PreallocShardBuilderError};
use crate::coordination::{
    CursorUpdate, ManifestValidationError, ShardArena, ShardSpecRef, validate_manifest,
};

#[test]
fn mixed_range_prefix_manifest_builds_valid_manifest() {
    let mut arena = ShardArena::with_capacity(8, 4_096);
    let mut builder = PreallocShardBuilder::<8>::new(&mut arena, 8).unwrap();
    builder.add_range(b"a", b"f", b"").unwrap();
    builder.add_prefix(b"m/", b"").unwrap();
    builder.add_manifest(7, 0, 10, b"").unwrap();

    let inputs = builder.build_inputs().unwrap();
    assert_eq!(inputs.len(), 3);
    validate_manifest(inputs.as_slice()).unwrap();
}

#[test]
fn ids_are_assigned_in_insertion_order() {
    let mut arena = ShardArena::with_capacity(8, 4_096);
    let mut builder = PreallocShardBuilder::<8>::new(&mut arena, 8).unwrap();
    builder.add_range(b"a", b"f", b"").unwrap();
    builder.add_prefix(b"m/", b"").unwrap();
    builder.add_manifest(7, 0, 10, b"").unwrap();

    let inputs = builder.build_inputs().unwrap();
    let ids: Vec<u64> = inputs.iter().map(|entry| entry.shard().as_raw()).collect();
    assert_eq!(ids, vec![0, 1, 2]);
}

#[test]
fn default_add_methods_use_initial_cursor() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    builder.add_range(b"a", b"b", b"").unwrap();

    let inputs = builder.build_inputs().unwrap();
    assert_eq!(inputs.len(), 1);
    let cursor = inputs.as_slice()[0].cursor();
    assert!(cursor.last_key().is_none());
    assert!(cursor.token().is_none());
}

#[test]
fn with_cursor_methods_preserve_non_initial_cursor() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    let cursor = CursorUpdate::with_token(b"a1", b"tok");
    builder
        .add_range_with_cursor(b"a", b"b", b"", cursor)
        .unwrap();
    builder
        .add_prefix_with_cursor(b"m/", b"", CursorUpdate::new(b"m/"))
        .unwrap();

    let inputs = builder.build_inputs().unwrap();
    assert_eq!(
        inputs.as_slice()[0].cursor().last_key(),
        Some(b"a1".as_slice())
    );
    assert_eq!(
        inputs.as_slice()[0].cursor().token(),
        Some(b"tok".as_slice())
    );
    assert_eq!(
        inputs.as_slice()[1].cursor().last_key(),
        Some(b"m/".as_slice())
    );
    assert!(inputs.as_slice()[1].cursor().token().is_none());
}

#[test]
fn overlapping_ranges_fail_on_build_validation() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    builder.add_range(b"a", b"m", b"").unwrap();
    builder.add_range(b"f", b"z", b"").unwrap();

    let err = builder.build_inputs().unwrap_err();
    assert!(matches!(
        err,
        PreallocShardBuilderError::ManifestInvalid(
            ManifestValidationError::OverlappingRanges { .. }
        )
    ));
}

#[test]
fn entry_limit_exhaustion_returns_capacity_exceeded() {
    let mut arena = ShardArena::with_capacity(2, 2_048);
    let mut builder = PreallocShardBuilder::<2>::new(&mut arena, 1).unwrap();
    builder.add_range(b"a", b"b", b"").unwrap();
    let err = builder.add_range(b"b", b"c", b"").unwrap_err();

    assert!(matches!(
        err,
        PreallocShardBuilderError::CapacityExceeded {
            limit: 1,
            current: 1,
            additional: 1
        }
    ));
}

#[test]
fn arena_slot_exhaustion_returns_slab_full() {
    let mut arena = ShardArena::with_capacity(1, 4_096);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    builder.add_range(b"a", b"b", b"").unwrap();
    let err = builder.add_range(b"b", b"c", b"").unwrap_err();

    assert!(matches!(err, PreallocShardBuilderError::SlabFull(_)));
}

#[test]
fn arena_byte_exhaustion_returns_slab_full() {
    let mut arena = ShardArena::with_capacity(4, 64);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    builder.add_range(b"a", b"b", b"").unwrap();
    let err = builder.add_range(b"c", b"d", b"").unwrap_err();

    assert!(matches!(err, PreallocShardBuilderError::SlabFull(_)));
}

#[test]
fn stale_or_foreign_handle_is_rejected_without_panic() {
    let mut foreign_arena = ShardArena::with_capacity(1, 256);
    let handle = foreign_arena
        .alloc_spec(ShardSpecRef::new(b"a", b"b", b""))
        .unwrap();
    foreign_arena.free_spec(handle);

    let mut arena = ShardArena::with_capacity(2, 512);
    let mut builder = PreallocShardBuilder::<2>::new(&mut arena, 2).unwrap();
    let err = builder.add_spec_handle(handle).unwrap_err();
    assert!(matches!(err, PreallocShardBuilderError::InvalidSpecHandle));
}

#[test]
fn reset_allows_fresh_reuse_and_resets_ids() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    builder.add_range(b"a", b"b", b"").unwrap();
    builder.add_range(b"b", b"c", b"").unwrap();
    assert_eq!(builder.len(), 2);

    builder.reset();
    assert!(builder.is_empty());
    assert_eq!(builder.remaining_entries(), 4);

    builder.add_prefix(b"m/", b"").unwrap();
    let inputs = builder.build_inputs().unwrap();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs.as_slice()[0].shard().as_raw(), 0);
}

// -- add_spec_ref ------------------------------------------------------------

#[test]
fn add_spec_ref_happy_path() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    let spec = ShardSpecRef::new(b"a", b"z", b"meta");
    let id = builder.add_spec_ref(spec).unwrap();
    assert_eq!(id.as_raw(), 0);
    let inputs = builder.build_inputs().unwrap();
    assert_eq!(inputs.as_slice()[0].spec().key_range_start(), b"a");
    assert_eq!(inputs.as_slice()[0].spec().metadata(), b"meta");
    assert!(inputs.as_slice()[0].cursor().last_key().is_none());
}

#[test]
fn add_spec_ref_rejects_inverted_range() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    let err = builder
        .add_spec_ref(ShardSpecRef::new(b"z", b"a", &[]))
        .unwrap_err();
    assert!(matches!(err, PreallocShardBuilderError::SpecInvalid(_)));
}

#[test]
fn add_spec_ref_slab_full() {
    let mut arena = ShardArena::with_capacity(1, 4_096);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    builder
        .add_spec_ref(ShardSpecRef::new(b"a", b"m", &[]))
        .unwrap();
    let err = builder
        .add_spec_ref(ShardSpecRef::new(b"m", b"z", &[]))
        .unwrap_err();
    assert!(matches!(err, PreallocShardBuilderError::SlabFull(_)));
}

// -- build_inputs on empty builder -------------------------------------------

#[test]
fn build_inputs_on_empty_builder_returns_manifest_empty() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    let err = builder.build_inputs().unwrap_err();
    assert!(matches!(
        err,
        PreallocShardBuilderError::ManifestInvalid(ManifestValidationError::Empty)
    ));
}

// -- Config validation -------------------------------------------------------

#[test]
fn config_rejects_zero_entry_limit() {
    let mut arena = ShardArena::with_capacity(4, 4_096);
    assert!(matches!(
        PreallocShardBuilder::<4>::new(&mut arena, 0),
        Err(PreallocShardBuilderError::EntryLimitZero)
    ));
}

#[test]
fn config_rejects_entry_limit_exceeding_cap() {
    let mut arena = ShardArena::with_capacity(4, 4_096);
    assert!(matches!(
        PreallocShardBuilder::<2>::new(&mut arena, 4),
        Err(PreallocShardBuilderError::CapMismatch {
            entry_limit: 4,
            cap: 2
        })
    ));
}

// -- Error-mapping paths -----------------------------------------------------

#[test]
fn add_range_with_inverted_bounds_returns_range_invalid() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    let err = builder.add_range(b"z", b"a", b"").unwrap_err();
    assert!(matches!(err, PreallocShardBuilderError::RangeInvalid(_)));
}

#[test]
fn add_prefix_with_empty_prefix_returns_prefix_invalid() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    let err = builder.add_prefix(b"", b"").unwrap_err();
    assert!(matches!(err, PreallocShardBuilderError::PrefixInvalid(_)));
}

#[test]
fn add_manifest_with_inverted_rows_returns_manifest_ctor_invalid() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    let err = builder.add_manifest(1, 10, 5, b"").unwrap_err();
    assert!(matches!(
        err,
        PreallocShardBuilderError::ManifestCtorInvalid(_)
    ));
}

// -- Cursor out of bounds at build time --------------------------------------

#[test]
fn cursor_outside_range_fails_manifest_validation() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    builder
        .add_range_with_cursor(b"a", b"f", b"", CursorUpdate::new(b"z"))
        .unwrap();
    let err = builder.build_inputs().unwrap_err();
    assert!(matches!(
        err,
        PreallocShardBuilderError::ManifestInvalid(
            ManifestValidationError::CursorOutOfBounds { .. }
        )
    ));
}

// -- Manifest with cursor ----------------------------------------------------

#[test]
fn add_manifest_with_cursor_preserves_initial_cursor() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    builder
        .add_manifest_with_cursor(7, 0, 10, b"", CursorUpdate::initial())
        .unwrap();
    let inputs = builder.build_inputs().unwrap();
    assert!(inputs.as_slice()[0].cursor().last_key().is_none());
}

#[test]
fn add_manifest_with_cursor_preserves_explicit_cursor() {
    // Manifest key encoding: BE(manifest_id) ++ BE(row), 16 bytes total.
    // For manifest_id=7, row range [0, 10), a cursor at row=5 is in-bounds.
    // Declared before arena/builder so it outlives the borrowed CursorUpdate.
    let mut cursor_key = [0u8; 16];
    cursor_key[..8].copy_from_slice(&7u64.to_be_bytes());
    cursor_key[8..].copy_from_slice(&5u64.to_be_bytes());
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    builder
        .add_manifest_with_cursor(7, 0, 10, b"", CursorUpdate::new(&cursor_key))
        .unwrap();
    let inputs = builder.build_inputs().unwrap();
    assert_eq!(
        inputs.as_slice()[0].cursor().last_key(),
        Some(cursor_key.as_slice())
    );
}

// -- build_inputs idempotency ------------------------------------------------

#[test]
fn build_inputs_is_idempotent() {
    let mut arena = ShardArena::with_capacity(4, 2_048);
    let mut builder = PreallocShardBuilder::<4>::new(&mut arena, 4).unwrap();
    builder.add_range(b"a", b"f", b"").unwrap();
    builder.add_prefix(b"m/", b"").unwrap();
    let first = builder.build_inputs().unwrap();
    let second = builder.build_inputs().unwrap();
    assert_eq!(first.len(), second.len());
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(a.shard().as_raw(), b.shard().as_raw());
        assert_eq!(a.spec().key_range_start(), b.spec().key_range_start());
    }
}
