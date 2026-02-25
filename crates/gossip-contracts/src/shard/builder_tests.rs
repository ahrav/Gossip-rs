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
