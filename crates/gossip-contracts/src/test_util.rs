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

/// Generate a [`ShardSpec`] covering all four boundedness variants:
/// fully bounded (weighted 4×), start-unbounded, end-unbounded, fully unbounded.
pub(crate) fn arb_shard_spec() -> impl Strategy<Value = ShardSpec> {
    proptest::prop_oneof![
        4 => arb_bounded_shard_spec(),
        1 => proptest::collection::vec(any::<u8>(), 1..64)
            .prop_map(|end| ShardSpec::with_range(vec![], end)),
        1 => proptest::collection::vec(any::<u8>(), 1..64)
            .prop_map(|start| ShardSpec::with_range(start, vec![])),
        1 => Just(ShardSpec::unbounded()),
    ]
}
