/// Returns a [`proptest::test_runner::Config`] tuned for the current environment.
///
/// Under Miri, disables file-based failure persistence (filesystem I/O is
/// blocked by Miri's default isolation mode) and reduces cases from the
/// proptest default of 256 to 32, since Miri interpretation is far slower
/// than native execution.
pub(crate) fn miri_proptest_config() -> proptest::test_runner::Config {
    if cfg!(miri) {
        proptest::test_runner::Config {
            failure_persistence: None,
            cases: 32,
            ..Default::default()
        }
    } else {
        proptest::test_runner::Config::default()
    }
}

/// Hash a value via [`CanonicalBytes`] and return the BLAKE3 digest.
///
/// Convenience wrapper used across test modules to verify determinism
/// and collision-freedom of canonical encodings.
pub(crate) fn canonical_digest<T: crate::identity::CanonicalBytes>(val: &T) -> blake3::Hash {
    let mut h = blake3::Hasher::new();
    val.write_canonical(&mut h);
    h.finalize()
}

// ---------------------------------------------------------------------------
// Proptest strategies for ShardSpec — shared across coordination test modules
// ---------------------------------------------------------------------------

use crate::coordination::ShardSpec;
use crate::coordination::cursor::Cursor;
use proptest::prelude::*;

/// Generate a valid bounded [`ShardSpec`]: end = start ++ non-empty suffix,
/// guaranteeing `start < end` lexicographically.
pub(crate) fn arb_bounded_shard_spec() -> impl Strategy<Value = ShardSpec> {
    (
        proptest::collection::vec(any::<u8>(), 1..64),
        proptest::collection::vec(any::<u8>(), 1..8),
    )
        .prop_map(|(start, suffix)| {
            let mut end = start.clone();
            end.extend_from_slice(&suffix);
            ShardSpec::with_range(start, end)
        })
}

/// Generate a valid bounded [`ShardSpec`] with non-empty metadata.
pub(crate) fn arb_bounded_shard_spec_with_metadata() -> impl Strategy<Value = ShardSpec> {
    (
        proptest::collection::vec(any::<u8>(), 1..64),
        proptest::collection::vec(any::<u8>(), 1..8),
        proptest::collection::vec(any::<u8>(), 1..128),
    )
        .prop_map(|(start, suffix, meta)| {
            let mut end = start.clone();
            end.extend_from_slice(&suffix);
            ShardSpec::with_range_and_metadata(start, end, meta)
        })
}

/// Generate a [`ShardSpec`] covering all four boundedness variants plus
/// a metadata variant: fully bounded (weight 4), bounded-with-metadata
/// (weight 2), start-unbounded, end-unbounded, fully unbounded.
pub(crate) fn arb_shard_spec() -> impl Strategy<Value = ShardSpec> {
    proptest::prop_oneof![
        4 => arb_bounded_shard_spec(),
        2 => arb_bounded_shard_spec_with_metadata(),
        1 => proptest::collection::vec(any::<u8>(), 1..64)
            .prop_map(|end| ShardSpec::with_range(vec![], end)),
        1 => proptest::collection::vec(any::<u8>(), 1..64)
            .prop_map(|start| ShardSpec::with_range(start, vec![])),
        1 => Just(ShardSpec::unbounded()),
    ]
}

/// Generate a valid [`Cursor`] covering all three states: initial (no
/// progress), last-key only, and last-key + token.
///
/// `last_key` and `token` are 1..64 non-empty byte vectors, matching the
/// `Cursor` constructor preconditions (`last_key` must not be empty).
pub(crate) fn arb_cursor() -> impl Strategy<Value = Cursor> {
    proptest::prop_oneof![
        1 => Just(Cursor::initial()),
        3 => proptest::collection::vec(any::<u8>(), 1..64)
            .prop_map(Cursor::with_last_key),
        3 => (
            proptest::collection::vec(any::<u8>(), 1..64),
            proptest::collection::vec(any::<u8>(), 1..64),
        )
            .prop_map(|(k, t)| Cursor::from_parts(k, t)),
    ]
}
