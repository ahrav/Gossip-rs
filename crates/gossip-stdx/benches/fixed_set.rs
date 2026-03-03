use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use gossip_stdx::FixedSet128;
use std::collections::HashSet;

const OPS_PER_ITER: u64 = 10_000;

// Simple xorshift for reproducible random keys.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u128(&mut self) -> u128 {
        let lo = self.next_u64() as u128;
        let hi = self.next_u64() as u128;
        (hi << 64) | lo
    }
}

fn make_u128_keys(count: usize, seed: u64) -> Vec<u128> {
    let mut rng = XorShift64::new(seed);
    (0..count).map(|_| rng.next_u128()).collect()
}

// ============================================================================
// 1. Basic Insert Performance
// ============================================================================

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_set/insert");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    let cap = 16384; // ~50% load factor with 10K ops
    let keys_128 = make_u128_keys(OPS_PER_ITER as usize, 0xdead_beef);

    group.bench_function("128bit_insert", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            for &key in &keys_128 {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    group.finish();
}

// ============================================================================
// 2. Load Factor Analysis
// ============================================================================

fn bench_load_factor(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_set/load_factor");

    // Test at various load factors: 25%, 50%, 75%, 90%, 99%
    let load_factors = [25, 50, 75, 90, 99];

    for &load_pct in &load_factors {
        // For N% load factor, we need cap = ops * 100 / N
        // Use 10K operations as baseline
        let ops = 10_000usize;
        let cap = (ops * 100 / load_pct).next_power_of_two();
        let keys = make_u128_keys(ops, 0xcafe_babe);
        group.throughput(Throughput::Elements(ops as u64));

        group.bench_with_input(
            BenchmarkId::new("insert_128", format!("{}%_load", load_pct)),
            &(cap, &keys),
            |b, (cap, keys)| {
                let mut set = FixedSet128::with_pow2(*cap);
                b.iter(|| {
                    set.reset();
                    for &key in *keys {
                        black_box(set.insert(black_box(key)));
                    }
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 3. Duplicate Detection (Primary Real-World Use Case)
// ============================================================================

fn make_keys_with_duplicates(unique_count: usize, total_count: usize, seed: u64) -> Vec<u128> {
    let unique_keys = make_u128_keys(unique_count, seed);
    let mut rng = XorShift64::new(seed ^ 0x1234);
    (0..total_count)
        .map(|_| unique_keys[(rng.next_u64() as usize) % unique_count])
        .collect()
}

fn bench_duplicate_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_set/duplicates");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    let cap = 16384;

    // 0% duplicates (all unique)
    let unique_keys = make_u128_keys(OPS_PER_ITER as usize, 0xaaaa_bbbb);
    group.bench_function("0%_duplicates", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            for &key in &unique_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // 50% duplicates
    let half_dup_keys = make_keys_with_duplicates(5000, OPS_PER_ITER as usize, 0xbbbb_cccc);
    group.bench_function("50%_duplicates", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            for &key in &half_dup_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // 90% duplicates
    let high_dup_keys = make_keys_with_duplicates(1000, OPS_PER_ITER as usize, 0xcccc_dddd);
    group.bench_function("90%_duplicates", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            for &key in &high_dup_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // 100% duplicates (same key repeated)
    let same_key = 0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0u128;
    group.bench_function("100%_duplicates", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            // Insert once, then re-insert same key
            set.insert(same_key);
            for _ in 1..OPS_PER_ITER {
                black_box(set.insert(black_box(same_key)));
            }
        })
    });

    group.finish();
}

// ============================================================================
// 4. Cache Behavior
// ============================================================================

fn bench_cache_behavior(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_set/cache");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    let cap = 16384;

    // Sequential keys (predictable access pattern).
    // FixedSet128 uses the upper 64 bits for the initial slot selection,
    // so we advance the high bits to produce sequential slots.
    group.bench_function("sequential_keys", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            for i in 0..OPS_PER_ITER {
                let key = (i as u128) << 64;
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // Random keys (unpredictable access pattern)
    let random_keys = make_u128_keys(OPS_PER_ITER as usize, 0x1234_5678);
    group.bench_function("random_keys", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            for &key in &random_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // Hot key repeated 10K times (L1 cache + branch prediction)
    let hot_key = 0xBEEF_CAFE_DEAD_F00D_0123_4567_89AB_CDEFu128;
    group.bench_function("hot_key_repeated", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            set.insert(hot_key); // First insert
            for _ in 1..OPS_PER_ITER {
                black_box(set.insert(black_box(hot_key)));
            }
        })
    });

    // Clustered keys (nearby slots, tests linear probing locality)
    let base_slot = 1000u64;
    let clustered_keys: Vec<u128> = (0..OPS_PER_ITER)
        .map(|i| ((base_slot + i) as u128) << 64)
        .collect();
    group.bench_function("clustered_keys", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            for &key in &clustered_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    group.finish();
}

// ============================================================================
// 5. HashSet Comparison (O(1) Reset Value)
// ============================================================================

fn bench_vs_hashset(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_set/vs_hashset");

    let keys = make_u128_keys(1000, 0xfeed_face);
    let iterations = 100u64;

    group.throughput(Throughput::Elements(iterations * keys.len() as u64));

    // FixedSet with reset
    group.bench_function("fixedset128_reset_insert", |b| {
        let mut set = FixedSet128::with_pow2(2048);
        b.iter(|| {
            for _ in 0..iterations {
                set.reset();
                for &key in &keys {
                    black_box(set.insert(black_box(key)));
                }
            }
        })
    });

    // HashSet<u128> with clear
    group.bench_function("hashset_u128_clear_insert", |b| {
        let mut set = HashSet::with_capacity(2048);
        b.iter(|| {
            for _ in 0..iterations {
                set.clear();
                for &key in &keys {
                    black_box(set.insert(black_box(key)));
                }
            }
        })
    });

    group.finish();
}

// ============================================================================
// 6. Scaling Analysis (Cache Pressure)
// ============================================================================

fn bench_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_set/scaling");

    // Table sizes: 1K, 4K, 16K, 64K, 256K, 1M
    // Memory per slot: FixedSet128 = 16 + 4 = 20 bytes
    // L1: ~32KB, L2: ~256KB, L3: ~6-12MB typical
    let sizes = [1024, 4096, 16384, 65536, 262144, 1048576];

    for &size in &sizes {
        // Insert 50% of capacity to get consistent load factor
        let ops = size / 2;
        let keys = make_u128_keys(ops, 0x9999_8888);

        group.throughput(Throughput::Elements(ops as u64));

        group.bench_with_input(
            BenchmarkId::new("128bit", format!("{}slots", size)),
            &(size, &keys),
            |b, (cap, keys)| {
                let mut set = FixedSet128::with_pow2(*cap);
                b.iter(|| {
                    set.reset();
                    for &key in *keys {
                        black_box(set.insert(black_box(key)));
                    }
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 7. Worst-Case Scenarios
// ============================================================================

fn bench_worst_case(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_set/worst_case");

    // Adversarial: keys that hash to the same slot (linear probing stress test)
    // FixedSet128 uses the upper 64 bits for slot selection, so keep them constant.
    let cap = 1024;
    let high = 0u64;

    // Create 100 keys that all hash to slot 0
    let adversarial_keys: Vec<u128> = (0..100)
        .map(|i| ((high as u128) << 64) | i as u128)
        .collect();

    group.throughput(Throughput::Elements(adversarial_keys.len() as u64));
    group.bench_function("same_slot_adversarial", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            for &key in &adversarial_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // Full table insertion (worst-case probing at near-capacity)
    let full_cap = 256;
    let full_keys = make_u128_keys(full_cap - 1, 0x7777_6666); // One less than full

    group.throughput(Throughput::Elements(full_keys.len() as u64));
    group.bench_function("near_full_table", |b| {
        let mut set = FixedSet128::with_pow2(full_cap);
        b.iter(|| {
            set.reset();
            for &key in &full_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // Insert into completely full table (triggers "table full" path)
    let overfill_keys = make_u128_keys(full_cap + 10, 0x5555_4444);
    group.throughput(Throughput::Elements(overfill_keys.len() as u64));
    group.bench_function("overfill_table", |b| {
        let mut set = FixedSet128::with_pow2(full_cap);
        b.iter(|| {
            set.reset();
            for &key in &overfill_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    group.finish();
}

// ============================================================================
// 8. Reset Performance
// ============================================================================

fn bench_reset(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_set/reset");

    for &cap in &[1024, 16384, 262144, 1048576] {
        group.bench_with_input(BenchmarkId::new("128bit", cap), &cap, |b, &cap| {
            let mut set = FixedSet128::with_pow2(cap);
            b.iter(|| {
                set.reset();
                black_box(());
            })
        });
    }

    group.finish();
}

// ============================================================================
// 9. Lookup-Heavy Workload (Mixed Insert + Duplicate Check)
// ============================================================================

fn bench_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_set/mixed");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    let cap = 16384;

    // Real-world pattern: insert many, then check many duplicates
    let initial_keys = make_u128_keys(5000, 0x1111_2222);
    let check_keys = make_u128_keys(5000, 0x1111_2222); // Same seed = same keys = duplicates

    group.bench_function("insert_then_check_dups", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            // Insert phase
            for &key in &initial_keys {
                set.insert(key);
            }
            // Duplicate check phase (all should return false)
            for &key in &check_keys {
                black_box(set.insert(black_box(key)));
            }
        })
    });

    // Interleaved: alternate between new and duplicate
    let new_keys = make_u128_keys(5000, 0x3333_4444);
    let dup_keys = make_u128_keys(5000, 0x3333_4444);

    group.bench_function("interleaved_new_dup", |b| {
        let mut set = FixedSet128::with_pow2(cap);
        b.iter(|| {
            set.reset();
            for i in 0..5000 {
                set.insert(new_keys[i]); // First insert (new)
                black_box(set.insert(black_box(dup_keys[i]))); // Second insert (dup)
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_insert,
    bench_load_factor,
    bench_duplicate_detection,
    bench_cache_behavior,
    bench_vs_hashset,
    bench_scaling,
    bench_worst_case,
    bench_reset,
    bench_mixed_workload,
);

criterion_main!(benches);
