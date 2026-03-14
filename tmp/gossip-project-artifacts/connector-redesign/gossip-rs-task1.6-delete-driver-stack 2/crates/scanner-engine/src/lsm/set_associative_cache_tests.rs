use super::{
    Options, PackedUnsignedIntegerArray, SetAssociativeCache, SetAssociativeCacheContext, Tag,
};
use proptest::prelude::*;

#[test]
fn packed_unsigned_integer_array_unit() {
    let mut array =
        PackedUnsignedIntegerArray::<2>::from_words(vec![0, 0b10110010, 0, 0, 0, 0, 0, 0]);

    assert_eq!(0b10, array.get(32));
    assert_eq!(0b00, array.get(32 + 1));
    assert_eq!(0b11, array.get(32 + 2));
    assert_eq!(0b10, array.get(32 + 3));

    array.set(0, 0b01);
    assert_eq!(0b00000001u64, array.words()[0]);
    assert_eq!(0b01, array.get(0));
    array.set(1, 0b10);
    assert_eq!(0b00001001u64, array.words()[0]);
    assert_eq!(0b10, array.get(1));
    array.set(2, 0b11);
    assert_eq!(0b00111001u64, array.words()[0]);
    assert_eq!(0b11, array.get(2));
    array.set(3, 0b11);
    assert_eq!(0b11111001u64, array.words()[0]);
    assert_eq!(0b11, array.get(3));
    array.set(3, 0b01);
    assert_eq!(0b01111001u64, array.words()[0]);
    assert_eq!(0b01, array.get(3));
    array.set(3, 0b00);
    assert_eq!(0b00111001u64, array.words()[0]);
    assert_eq!(0b00, array.get(3));

    array.set(4, 0b11);
    assert_eq!(
        0b0000000000000000000000000000000000000000000000000000001100111001u64,
        array.words()[0],
    );
    array.set(31, 0b11);
    assert_eq!(
        0b1100000000000000000000000000000000000000000000000000001100111001u64,
        array.words()[0],
    );
}

const LEN: usize = 1024;

fn packed_unsigned_integer_array_case<const BITS: usize>(ops: &[(usize, u8)]) {
    let words_len = PackedUnsignedIntegerArray::<BITS>::words_for_len(LEN);
    let mut array = PackedUnsignedIntegerArray::<BITS>::new_zeroed(words_len);
    let mut reference = vec![0u8; LEN];

    for &(index, value) in ops {
        array.set(index as u64, value);
        reference[index] = value;

        for (i, &expected) in reference.iter().enumerate() {
            assert_eq!(expected, array.get(i as u64));
        }
    }
}

fn packed_unsigned_integer_array_ops<const BITS: usize>() -> impl Strategy<Value = Vec<(usize, u8)>>
{
    let mask = ((1u16 << BITS) - 1) as u8;
    prop::collection::vec((0usize..LEN, 0u8..=mask), 0..512)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        crate::test_utils::proptest_cases(16)
    ))]

    #[test]
    fn packed_unsigned_integer_array_prop_u1(ops in packed_unsigned_integer_array_ops::<1>()) {
        packed_unsigned_integer_array_case::<1>(&ops);
    }

    #[test]
    fn packed_unsigned_integer_array_prop_u2(ops in packed_unsigned_integer_array_ops::<2>()) {
        packed_unsigned_integer_array_case::<2>(&ops);
    }

    #[test]
    fn packed_unsigned_integer_array_prop_u4(ops in packed_unsigned_integer_array_ops::<4>()) {
        packed_unsigned_integer_array_case::<4>(&ops);
    }
}

fn packed_unsigned_integer_array_ops_fuzz<const BITS: usize>()
-> impl Strategy<Value = Vec<(usize, u8)>> {
    let mask = ((1u16 << BITS) - 1) as u8;
    prop::collection::vec((0usize..LEN, 0u8..=mask), 10_000)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        crate::test_utils::proptest_cases(1)
    ))]

    #[test]
    fn packed_unsigned_integer_array_prop_fuzz_u1(
        ops in packed_unsigned_integer_array_ops_fuzz::<1>()
    ) {
        packed_unsigned_integer_array_case::<1>(&ops);
    }

    #[test]
    fn packed_unsigned_integer_array_prop_fuzz_u2(
        ops in packed_unsigned_integer_array_ops_fuzz::<2>()
    ) {
        packed_unsigned_integer_array_case::<2>(&ops);
    }

    #[test]
    fn packed_unsigned_integer_array_prop_fuzz_u4(
        ops in packed_unsigned_integer_array_ops_fuzz::<4>()
    ) {
        packed_unsigned_integer_array_case::<4>(&ops);
    }
}

struct IdentityContext;

impl SetAssociativeCacheContext for IdentityContext {
    type Key = u64;
    type Value = u64;

    fn key_from_value(value: &Self::Value) -> Self::Key {
        *value
    }

    fn hash(key: Self::Key) -> u64 {
        key
    }
}

struct CollisionContext;

impl SetAssociativeCacheContext for CollisionContext {
    type Key = u64;
    type Value = u64;

    fn key_from_value(value: &Self::Value) -> Self::Key {
        *value
    }

    fn hash(_: Self::Key) -> u64 {
        0
    }
}

type EvictionCache<C> = SetAssociativeCache<'static, C, u8, 16, 2, 64, 0, 4>;
type SearchTagsCache<TagT, const WAYS: usize, const CLOCK_HAND_BITS: usize> =
    SetAssociativeCache<'static, IdentityContext, TagT, WAYS, 2, 64, 0, CLOCK_HAND_BITS>;

fn assert_cache_zeroed<C>(sac: &EvictionCache<C>)
where
    C: SetAssociativeCacheContext,
{
    for &tag in sac.tags.iter() {
        assert_eq!(0, tag);
    }
    // SAFETY: We have exclusive access to `sac` via shared reference in a single-threaded
    // test, so dereferencing the `UnsafeCell` pointers for `counts` and `clocks` is safe.
    unsafe {
        for &word in (*sac.counts.get()).words().iter() {
            assert_eq!(0, word);
        }
        for &word in (*sac.clocks.get()).words().iter() {
            assert_eq!(0, word);
        }
    }
}

fn run_set_associative_cache_test<C>()
where
    C: SetAssociativeCacheContext<Key = u64, Value = u64>,
{
    const WAYS: usize = 16;
    const CLOCK_BITS: usize = 2;
    let mut sac = EvictionCache::<C>::init(16 * 16 * 8, Options { name: "test" });

    assert_cache_zeroed(&sac);

    for i in 0..WAYS {
        assert_eq!(i as u8, sac.clocks_get(0));

        let key = (i as u64) * sac.sets;
        let _ = sac.upsert(&key);
        assert_eq!(1, sac.counts_get(i as u64));
        // SAFETY: `get` returned `Some`, so the pointer is valid and the value was just inserted.
        let value = unsafe { *sac.get(key).unwrap() };
        assert_eq!(key, value);
        assert_eq!(2, sac.counts_get(i as u64));
    }
    assert_eq!(0, sac.clocks_get(0));

    {
        let key = (WAYS as u64) * sac.sets;
        let _ = sac.upsert(&key);
        assert_eq!(1, sac.counts_get(0));
        // SAFETY: `get` returned `Some`, so the pointer is valid and the value was just inserted.
        let value = unsafe { *sac.get(key).unwrap() };
        assert_eq!(key, value);
        assert_eq!(2, sac.counts_get(0));

        assert!(sac.get(0).is_none());

        for i in 1..WAYS {
            assert_eq!(1, sac.counts_get(i as u64));
        }
    }

    {
        let key = 5u64 * sac.sets;
        // SAFETY: `get` returned `Some`, so the pointer is valid and the key is still present.
        let value = unsafe { *sac.get(key).unwrap() };
        assert_eq!(key, value);
        assert_eq!(2, sac.counts_get(5));

        assert_eq!(Some(key), sac.remove(key));
        assert!(sac.get(key).is_none());
        assert_eq!(0, sac.counts_get(5));
    }

    sac.reset();
    assert_cache_zeroed(&sac);

    let max_count = ((1u16 << CLOCK_BITS) - 1) as u8;
    for i in 0..WAYS {
        assert_eq!(i as u8, sac.clocks_get(0));

        let key = (i as u64) * sac.sets;
        let _ = sac.upsert(&key);
        assert_eq!(1, sac.counts_get(i as u64));
        for expected in 2u8..=max_count {
            // SAFETY: `get` returned `Some`, so the pointer is valid and the key is present.
            let value = unsafe { *sac.get(key).unwrap() };
            assert_eq!(key, value);
            assert_eq!(expected, sac.counts_get(i as u64));
        }
        // SAFETY: `get` returned `Some`, so the pointer is valid and the key is present.
        let value = unsafe { *sac.get(key).unwrap() };
        assert_eq!(key, value);
        assert_eq!(max_count, sac.counts_get(i as u64));
    }
    assert_eq!(0, sac.clocks_get(0));

    {
        let key = (WAYS as u64) * sac.sets;
        let _ = sac.upsert(&key);
        assert_eq!(1, sac.counts_get(0));
        // SAFETY: `get` returned `Some`, so the pointer is valid and the value was just inserted.
        let value = unsafe { *sac.get(key).unwrap() };
        assert_eq!(key, value);
        assert_eq!(2, sac.counts_get(0));

        assert!(sac.get(0).is_none());

        for i in 1..WAYS {
            assert_eq!(1, sac.counts_get(i as u64));
        }
    }
}

#[test]
fn set_associative_cache_eviction() {
    run_set_associative_cache_test::<IdentityContext>();
}

#[test]
fn set_associative_cache_hash_collision() {
    run_set_associative_cache_test::<CollisionContext>();
}

fn search_tags_expected<TagT: Tag, const WAYS: usize>(tags: &[TagT; WAYS], tag: TagT) -> u16 {
    let mut bits = 0u16;
    let mut count = 0usize;
    for (i, &t) in tags.iter().enumerate() {
        if t == tag {
            bits |= 1u16 << i;
            count += 1;
        }
    }
    assert_eq!(count, bits.count_ones() as usize);
    bits
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        crate::test_utils::proptest_cases(32)
    ))]

    #[test]
    fn set_associative_cache_search_tags_u8_2(
        mut tags in prop::array::uniform::<_, 2>(any::<u8>()),
        tag in any::<u8>(),
        mask in prop::array::uniform::<_, 2>(any::<bool>()),
    ) {
        for (slot, match_tag) in tags.iter_mut().zip(mask.into_iter()) {
            if match_tag {
                *slot = tag;
            }
        }

        let expected = search_tags_expected::<u8, 2>(&tags, tag);
        let actual = SearchTagsCache::<u8, 2, 1>::search_tags(&tags, tag);
        prop_assert_eq!(expected, actual);
    }

    #[test]
    fn set_associative_cache_search_tags_u8_4(
        mut tags in prop::array::uniform::<_, 4>(any::<u8>()),
        tag in any::<u8>(),
        mask in prop::array::uniform::<_, 4>(any::<bool>()),
    ) {
        for (slot, match_tag) in tags.iter_mut().zip(mask.into_iter()) {
            if match_tag {
                *slot = tag;
            }
        }

        let expected = search_tags_expected::<u8, 4>(&tags, tag);
        let actual = SearchTagsCache::<u8, 4, 2>::search_tags(&tags, tag);
        prop_assert_eq!(expected, actual);
    }

    #[test]
    fn set_associative_cache_search_tags_u8_16(
        mut tags in prop::array::uniform::<_, 16>(any::<u8>()),
        tag in any::<u8>(),
        mask in prop::array::uniform::<_, 16>(any::<bool>()),
    ) {
        for (slot, match_tag) in tags.iter_mut().zip(mask.into_iter()) {
            if match_tag {
                *slot = tag;
            }
        }

        let expected = search_tags_expected::<u8, 16>(&tags, tag);
        let actual = SearchTagsCache::<u8, 16, 4>::search_tags(&tags, tag);
        prop_assert_eq!(expected, actual);
    }

    #[test]
    fn set_associative_cache_search_tags_u16_2(
        mut tags in prop::array::uniform::<_, 2>(any::<u16>()),
        tag in any::<u16>(),
        mask in prop::array::uniform::<_, 2>(any::<bool>()),
    ) {
        for (slot, match_tag) in tags.iter_mut().zip(mask.into_iter()) {
            if match_tag {
                *slot = tag;
            }
        }

        let expected = search_tags_expected::<u16, 2>(&tags, tag);
        let actual = SearchTagsCache::<u16, 2, 1>::search_tags(&tags, tag);
        prop_assert_eq!(expected, actual);
    }

    #[test]
    fn set_associative_cache_search_tags_u16_4(
        mut tags in prop::array::uniform::<_, 4>(any::<u16>()),
        tag in any::<u16>(),
        mask in prop::array::uniform::<_, 4>(any::<bool>()),
    ) {
        for (slot, match_tag) in tags.iter_mut().zip(mask.into_iter()) {
            if match_tag {
                *slot = tag;
            }
        }

        let expected = search_tags_expected::<u16, 4>(&tags, tag);
        let actual = SearchTagsCache::<u16, 4, 2>::search_tags(&tags, tag);
        prop_assert_eq!(expected, actual);
    }

    #[test]
    fn set_associative_cache_search_tags_u16_16(
        mut tags in prop::array::uniform::<_, 16>(any::<u16>()),
        tag in any::<u16>(),
        mask in prop::array::uniform::<_, 16>(any::<bool>()),
    ) {
        for (slot, match_tag) in tags.iter_mut().zip(mask.into_iter()) {
            if match_tag {
                *slot = tag;
            }
        }

        let expected = search_tags_expected::<u16, 16>(&tags, tag);
        let actual = SearchTagsCache::<u16, 16, 4>::search_tags(&tags, tag);
        prop_assert_eq!(expected, actual);
    }
}

// ---- AVX2 compress_u16_mask equivalence ----

// Verify that the 32-bit compress (used by AVX2 u16 path) produces the same
// result as splitting into two 16-bit compresses and combining (SSE2 approach).
#[cfg(target_arch = "x86_64")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        crate::test_utils::proptest_cases(64)
    ))]

    #[test]
    fn compress_u16_mask_avx2_matches_split(raw_mask in any::<u32>()) {
        // Simulate _mm256_cmpeq_epi16 output: each u16 lane produces either
        // 0x0000 (no match) or 0xFFFF (match) in the movemask, yielding pairs
        // of identical bits. Constrain input to valid movemask patterns.
        let mut valid_mask = 0u32;
        for lane in 0..16u32 {
            if raw_mask & (1 << lane) != 0 {
                valid_mask |= 0b11 << (lane * 2);
            }
        }

        let avx2_result = SearchTagsCache::<u16, 16, 4>::compress_u16_mask_avx2(valid_mask);

        // SSE2 approach: split into low/high 16-bit halves, compress each.
        let lo = SearchTagsCache::<u16, 16, 4>::compress_u16_mask(valid_mask as u16);
        let hi = SearchTagsCache::<u16, 16, 4>::compress_u16_mask((valid_mask >> 16) as u16);
        let sse2_result = lo | (hi << 8);

        prop_assert_eq!(avx2_result, sse2_result,
            "mask=0x{:08X} avx2=0x{:04X} sse2=0x{:04X}", valid_mask, avx2_result, sse2_result);
    }
}

// ---- Additional property tests for hot paths ----

/// Context that hashes with a good distribution for testing associate().
struct HashingContext;

impl SetAssociativeCacheContext for HashingContext {
    type Key = u64;
    type Value = u64;

    fn key_from_value(value: &Self::Value) -> Self::Key {
        *value
    }

    fn hash(key: Self::Key) -> u64 {
        // FxHash-style mixing for good distribution
        const K: u64 = 0x517cc1b727220a95;
        key.wrapping_mul(K)
    }
}

type HashingCache = SetAssociativeCache<'static, HashingContext, u8, 16, 2, 64, 0, 4>;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        crate::test_utils::proptest_cases(8)
    ))]

    /// Verify associate() produces reasonable set distribution via fast_range.
    /// Chi-squared test: distribution should not be pathologically skewed.
    #[test]
    fn associate_distribution_prop(keys in prop::collection::vec(any::<u64>(), 1000..2000)) {
        let num_sets = 64u64;
        let cache_slots = num_sets * 16;
        let value_count = HashingCache::VALUE_COUNT_MAX_MULTIPLE;
        let adjusted_slots = ((cache_slots / value_count) * value_count).max(value_count);

        let cache = HashingCache::init(adjusted_slots, Options { name: "dist_test" });
        let actual_sets = cache.sets;

        let mut distribution = vec![0u64; actual_sets as usize];
        for &key in &keys {
            let set = cache.associate(key);
            let set_index = set.offset / 16;
            distribution[set_index as usize] += 1;
        }

        // Chi-squared test for uniformity.
        // Expected count per set if perfectly uniform.
        let expected = keys.len() as f64 / actual_sets as f64;
        let chi_squared: f64 = distribution
            .iter()
            .map(|&count| {
                let diff = count as f64 - expected;
                (diff * diff) / expected
            })
            .sum();

        // For df = actual_sets - 1, chi-squared critical value at p=0.001 is approximately
        // 2 * df for large df. We use a more conservative threshold.
        let critical = 3.0 * actual_sets as f64;
        prop_assert!(
            chi_squared < critical,
            "Distribution too skewed: chi_squared={:.2} >= critical={:.2}",
            chi_squared,
            critical
        );
    }

    /// Verify search() finds correct key despite tag collisions.
    /// Multiple keys may have the same tag but different values.
    #[test]
    fn search_with_tag_collisions_prop(
        base_key in 0u64..1000,
        num_entries in 2usize..16,
    ) {
        let cache_slots = 16 * 16;
        let value_count = HashingCache::VALUE_COUNT_MAX_MULTIPLE;
        let adjusted_slots = ((cache_slots as u64 / value_count) * value_count).max(value_count);

        let mut cache = HashingCache::init(adjusted_slots, Options { name: "collision_test" });

        // Generate keys that map to the same set (use cache.sets as multiplier).
        let keys: Vec<u64> = (0..num_entries)
            .map(|i| base_key + (i as u64) * cache.sets)
            .collect();

        // Insert all keys.
        for &key in &keys {
            cache.upsert(&key);
        }

        // Verify each key can be found and returns correct value.
        for &key in &keys {
            let ptr = cache.get(key);
            prop_assert!(ptr.is_some(), "Key {} should be present", key);
            // SAFETY: `get` returned `Some`, so the pointer is valid and the key is present.
            let value = unsafe { *ptr.unwrap() };
            prop_assert_eq!(key, value, "Value mismatch for key {}", key);
        }

        // Verify keys not in the cache return None.
        let absent_key = base_key + (num_entries as u64 + 10) * cache.sets;
        prop_assert!(cache.get(absent_key).is_none(), "Absent key should not be found");
    }

    /// Verify cache consistency under interleaved get/upsert workload.
    #[test]
    fn get_upsert_interleaved_prop(
        ops in prop::collection::vec(
            prop_oneof![
                (Just(true), 0u64..500),   // get operation
                (Just(false), 0u64..500),  // upsert operation
            ],
            100..500
        )
    ) {
        let cache_slots = 32 * 16;
        let value_count = HashingCache::VALUE_COUNT_MAX_MULTIPLE;
        let adjusted_slots = ((cache_slots as u64 / value_count) * value_count).max(value_count);

        let mut cache = HashingCache::init(adjusted_slots, Options { name: "interleaved_test" });
        let mut reference = std::collections::HashSet::<u64>::new();

        for (is_get, key) in ops {
            if is_get {
                // Get operation: if key is in reference, it should be in cache.
                // Note: cache may have evicted the key, so we can't assert presence.
                if let Some(ptr) = cache.get(key) {
                    // SAFETY: `get` returned `Some`, so the pointer is valid and points to the cached value.
                    let value = unsafe { *ptr };
                    prop_assert_eq!(key, value, "Value mismatch on get");
                }
            } else {
                // Upsert operation.
                cache.upsert(&key);
                reference.insert(key);

                // Immediately verify the just-inserted key is present.
                let ptr = cache.get(key);
                prop_assert!(ptr.is_some(), "Just-inserted key {} should be present", key);
                // SAFETY: `get` returned `Some`, so the pointer is valid; the key was just inserted.
                let value = unsafe { *ptr.unwrap() };
                prop_assert_eq!(key, value, "Value mismatch after upsert");
            }
        }
    }
}
