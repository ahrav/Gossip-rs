/// Returns a [`proptest::test_runner::Config`] tuned for the current environment.
///
/// Under Miri, disables file-based failure persistence (filesystem I/O is
/// blocked by Miri's default isolation mode) and reduces cases from the
/// proptest default of 256 to 32, since Miri interpretation is far slower
/// than native execution.
pub fn miri_proptest_config() -> proptest::test_runner::Config {
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

/// Hash a value via [`CanonicalBytes`](crate::identity::CanonicalBytes) and return the BLAKE3 digest.
///
/// Convenience wrapper used across test modules to verify determinism
/// and collision-freedom of canonical encodings.
pub fn canonical_digest<T: crate::identity::CanonicalBytes>(val: &T) -> blake3::Hash {
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
pub fn arb_bounded_shard_spec() -> impl Strategy<Value = ShardSpec> {
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
pub fn arb_bounded_shard_spec_with_metadata() -> impl Strategy<Value = ShardSpec> {
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
pub fn arb_shard_spec() -> impl Strategy<Value = ShardSpec> {
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

/// Generate a valid parent [`ShardSpec`] plus 2–4 contiguous children whose
/// ranges form an exact partition of the parent's `[start, end)` interval.
///
/// Uses suffix accumulation (same proven pattern as [`arb_bounded_shard_spec`])
/// to guarantee strict lexicographic ordering at each boundary.
pub fn arb_valid_n_way_split() -> impl Strategy<Value = (ShardSpec, Vec<ShardSpec>)> {
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

/// Generate a valid parent [`ShardSpec`] plus a split point guaranteed to be
/// strictly between `parent.start` and `parent.end`.
///
/// Uses suffix accumulation (same proven pattern as [`arb_bounded_shard_spec`])
/// to guarantee strict lexicographic ordering: `start < split_point < end`.
pub fn arb_residual_split() -> impl Strategy<Value = (ShardSpec, Vec<u8>)> {
    (
        proptest::collection::vec(any::<u8>(), 1..16),
        proptest::collection::vec(any::<u8>(), 1..8),
        proptest::collection::vec(any::<u8>(), 1..8),
    )
        .prop_map(|(base, suffix1, suffix2)| {
            let start = base.clone();
            let mut split_point = base;
            split_point.extend_from_slice(&suffix1);
            let mut end = split_point.clone();
            end.extend_from_slice(&suffix2);
            let parent = ShardSpec::with_range(start, end);
            (parent, split_point)
        })
}

// ---------------------------------------------------------------------------
// TestSlab — shared drop-safe slab wrapper for test code
// ---------------------------------------------------------------------------

/// Test slab wrapper that clears live allocations on drop.
///
/// In test code, records are often created but not explicitly deallocated
/// before the slab drops. This wrapper calls `clear()` in its `Drop` impl
/// so the slab's debug leak detector does not panic.
pub struct TestSlab(gossip_stdx::ByteSlab);

impl TestSlab {
    pub fn new() -> Self {
        Self(gossip_stdx::ByteSlab::with_capacity(64 * 1024))
    }
}

impl Default for TestSlab {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for TestSlab {
    type Target = gossip_stdx::ByteSlab;
    fn deref(&self) -> &gossip_stdx::ByteSlab {
        &self.0
    }
}

impl std::ops::DerefMut for TestSlab {
    fn deref_mut(&mut self) -> &mut gossip_stdx::ByteSlab {
        &mut self.0
    }
}

impl Drop for TestSlab {
    fn drop(&mut self) {
        self.0.clear();
    }
}
