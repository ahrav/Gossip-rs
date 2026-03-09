//! Benchmarks for SetAssociativeCache performance analysis.
//!
//! Benchmark dimensions:
//! - Cache size: small (256, L1), medium (16K, L2/L3), large (256K, RAM)
//! - WAYS: 2, 4, 16
//! - Tag type: u8, u16
//! - Operations: get_hit, get_miss, upsert_insert, upsert_update, mixed
//! - Value size: 16B (SmallValue), 128B (LargeValue)

use core::mem::size_of;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use scanner_engine::lsm::set_associative_cache::{
    Options, PackedUnsignedIntegerArray, SetAssociativeCache, SetAssociativeCacheContext,
};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::hint::black_box;

const DEFAULT_OPS: usize = 10_000;
const CACHE_LINE_SIZE: usize = 64;

// ---- Value types ----

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct SmallValue {
    key: u64,
    payload: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct LargeValue {
    key: u64,
    payload: [u8; 120],
}

const _: () = assert!(size_of::<SmallValue>() == 16);
const _: () = assert!(size_of::<LargeValue>() == 128);

// ---- Context implementations ----

struct SmallValueContext;
struct LargeValueContext;

impl SetAssociativeCacheContext for SmallValueContext {
    type Key = u64;
    type Value = SmallValue;

    fn key_from_value(value: &Self::Value) -> Self::Key {
        value.key
    }

    fn hash(key: Self::Key) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }
}

impl SetAssociativeCacheContext for LargeValueContext {
    type Key = u64;
    type Value = LargeValue;

    fn key_from_value(value: &Self::Value) -> Self::Key {
        value.key
    }

    fn hash(key: Self::Key) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }
}

// ---- Cache type aliases ----

type SmallCache16Way =
    SetAssociativeCache<'static, SmallValueContext, u8, 16, 2, CACHE_LINE_SIZE, 0, 4>;
type SmallCache4Way =
    SetAssociativeCache<'static, SmallValueContext, u8, 4, 2, CACHE_LINE_SIZE, 0, 2>;
type SmallCache2Way =
    SetAssociativeCache<'static, SmallValueContext, u8, 2, 2, CACHE_LINE_SIZE, 0, 1>;

type LargeCache16Way =
    SetAssociativeCache<'static, LargeValueContext, u8, 16, 2, CACHE_LINE_SIZE, 0, 4>;

// ---- Benchmark fixtures ----

struct Fixture<V> {
    /// Keys that are in the cache (for hit testing)
    present_keys: Vec<u64>,
    /// Keys that are NOT in the cache (for miss testing)
    absent_keys: Vec<u64>,
    /// Values corresponding to present_keys
    values: Vec<V>,
}

fn build_fixture_small(capacity: usize, runner: &mut TestRunner) -> Fixture<SmallValue> {
    // Generate unique keys for present/absent sets
    let key_strategy = any::<u64>();

    let mut present_keys = Vec::with_capacity(capacity);
    let mut values = Vec::with_capacity(capacity);

    for i in 0..capacity {
        let key = key_strategy.new_tree(runner).unwrap().current();
        // Ensure uniqueness by combining with index
        let unique_key = key.wrapping_add((i as u64).wrapping_mul(0x9E3779B97F4A7C15));
        present_keys.push(unique_key);
        values.push(SmallValue {
            key: unique_key,
            payload: i as u64,
        });
    }

    // Generate absent keys (high bits set differently to avoid collision)
    let absent_keys: Vec<u64> = (0..capacity)
        .map(|i| {
            let key = key_strategy.new_tree(runner).unwrap().current();
            key.wrapping_add(((capacity + i) as u64).wrapping_mul(0xC6A4A7935BD1E995))
                | (1u64 << 63)
        })
        .collect();

    Fixture {
        present_keys,
        absent_keys,
        values,
    }
}

fn build_fixture_large(capacity: usize, runner: &mut TestRunner) -> Fixture<LargeValue> {
    let key_strategy = any::<u64>();

    let mut present_keys = Vec::with_capacity(capacity);
    let mut values = Vec::with_capacity(capacity);

    for i in 0..capacity {
        let key = key_strategy.new_tree(runner).unwrap().current();
        let unique_key = key.wrapping_add((i as u64).wrapping_mul(0x9E3779B97F4A7C15));
        present_keys.push(unique_key);
        values.push(LargeValue {
            key: unique_key,
            payload: [0u8; 120],
        });
    }

    let absent_keys: Vec<u64> = (0..capacity)
        .map(|i| {
            let key = key_strategy.new_tree(runner).unwrap().current();
            key.wrapping_add(((capacity + i) as u64).wrapping_mul(0xC6A4A7935BD1E995))
                | (1u64 << 63)
        })
        .collect();

    Fixture {
        present_keys,
        absent_keys,
        values,
    }
}

// ---- PackedUnsignedIntegerArray benchmarks ----

fn bench_packed_array_get_set(c: &mut Criterion) {
    let mut group = c.benchmark_group("packed_array");
    let array_len = 16384usize;

    // 1-bit packed array
    {
        let words_len = PackedUnsignedIntegerArray::<1>::words_for_len(array_len);
        let array = PackedUnsignedIntegerArray::<1>::new_zeroed(words_len);

        group.throughput(Throughput::Elements(DEFAULT_OPS as u64));
        group.bench_function(BenchmarkId::new("get", "bits=1"), |b| {
            b.iter(|| {
                let mut sum = 0u64;
                for i in 0..DEFAULT_OPS {
                    sum = sum.wrapping_add(array.get((i % array_len) as u64) as u64);
                }
                black_box(sum)
            });
        });

        group.bench_function(BenchmarkId::new("set", "bits=1"), |b| {
            b.iter_batched(
                || PackedUnsignedIntegerArray::<1>::new_zeroed(words_len),
                |mut arr| {
                    for i in 0..DEFAULT_OPS {
                        arr.set((i % array_len) as u64, (i & 1) as u8);
                    }
                    black_box(arr.words().len())
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    // 2-bit packed array
    {
        let words_len = PackedUnsignedIntegerArray::<2>::words_for_len(array_len);
        let array = PackedUnsignedIntegerArray::<2>::new_zeroed(words_len);

        group.throughput(Throughput::Elements(DEFAULT_OPS as u64));
        group.bench_function(BenchmarkId::new("get", "bits=2"), |b| {
            b.iter(|| {
                let mut sum = 0u64;
                for i in 0..DEFAULT_OPS {
                    sum = sum.wrapping_add(array.get((i % array_len) as u64) as u64);
                }
                black_box(sum)
            });
        });

        group.bench_function(BenchmarkId::new("set", "bits=2"), |b| {
            b.iter_batched(
                || PackedUnsignedIntegerArray::<2>::new_zeroed(words_len),
                |mut arr| {
                    for i in 0..DEFAULT_OPS {
                        arr.set((i % array_len) as u64, (i & 3) as u8);
                    }
                    black_box(arr.words().len())
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    // 4-bit packed array
    {
        let words_len = PackedUnsignedIntegerArray::<4>::words_for_len(array_len);
        let array = PackedUnsignedIntegerArray::<4>::new_zeroed(words_len);

        group.throughput(Throughput::Elements(DEFAULT_OPS as u64));
        group.bench_function(BenchmarkId::new("get", "bits=4"), |b| {
            b.iter(|| {
                let mut sum = 0u64;
                for i in 0..DEFAULT_OPS {
                    sum = sum.wrapping_add(array.get((i % array_len) as u64) as u64);
                }
                black_box(sum)
            });
        });

        group.bench_function(BenchmarkId::new("set", "bits=4"), |b| {
            b.iter_batched(
                || PackedUnsignedIntegerArray::<4>::new_zeroed(words_len),
                |mut arr| {
                    for i in 0..DEFAULT_OPS {
                        arr.set((i % array_len) as u64, (i & 15) as u8);
                    }
                    black_box(arr.words().len())
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

// ---- Cache operation benchmarks ----

fn bench_cache_get_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_get_hit");
    let mut runner = TestRunner::deterministic();

    // Small values, 16-way, varying sizes
    for capacity in [256usize, 16 * 1024, 256 * 1024] {
        let cache_slots = (capacity / 16) * 16; // Round to multiple of WAYS
        let actual_capacity = cache_slots.min(16 * 1024); // Limit for reasonable test time

        let fixture = build_fixture_small(actual_capacity, &mut runner);
        let value_count = SmallCache16Way::VALUE_COUNT_MAX_MULTIPLE as usize;
        let adjusted_slots = ((cache_slots / value_count) * value_count).max(value_count);

        let mut cache = SmallCache16Way::init(adjusted_slots as u64, Options { name: "bench" });

        // Pre-populate cache
        for value in &fixture.values {
            cache.upsert(value);
        }

        group.throughput(Throughput::Elements(DEFAULT_OPS as u64));
        group.bench_function(
            BenchmarkId::new("16way_small", format!("capacity={}", capacity)),
            |b| {
                b.iter(|| {
                    let mut hits = 0u64;
                    for i in 0..DEFAULT_OPS {
                        let key = fixture.present_keys[i % fixture.present_keys.len()];
                        if cache.get(key).is_some() {
                            hits += 1;
                        }
                    }
                    black_box(hits)
                });
            },
        );
    }

    group.finish();
}

fn bench_cache_get_miss(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_get_miss");
    let mut runner = TestRunner::deterministic();

    for capacity in [256usize, 16 * 1024, 256 * 1024] {
        let cache_slots = (capacity / 16) * 16;
        let actual_capacity = cache_slots.min(16 * 1024);

        let fixture = build_fixture_small(actual_capacity, &mut runner);
        let value_count = SmallCache16Way::VALUE_COUNT_MAX_MULTIPLE as usize;
        let adjusted_slots = ((cache_slots / value_count) * value_count).max(value_count);

        let mut cache = SmallCache16Way::init(adjusted_slots as u64, Options { name: "bench" });

        // Pre-populate cache
        for value in &fixture.values {
            cache.upsert(value);
        }

        group.throughput(Throughput::Elements(DEFAULT_OPS as u64));
        group.bench_function(
            BenchmarkId::new("16way_small", format!("capacity={}", capacity)),
            |b| {
                b.iter(|| {
                    let mut misses = 0u64;
                    for i in 0..DEFAULT_OPS {
                        let key = fixture.absent_keys[i % fixture.absent_keys.len()];
                        if cache.get(key).is_none() {
                            misses += 1;
                        }
                    }
                    black_box(misses)
                });
            },
        );
    }

    group.finish();
}

fn bench_cache_upsert_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_upsert_insert");
    let mut runner = TestRunner::deterministic();

    for capacity in [256usize, 16 * 1024, 256 * 1024] {
        let cache_slots = (capacity / 16) * 16;
        let actual_capacity = cache_slots.min(16 * 1024);

        let fixture = build_fixture_small(actual_capacity, &mut runner);
        let value_count = SmallCache16Way::VALUE_COUNT_MAX_MULTIPLE as usize;
        let adjusted_slots = ((cache_slots / value_count) * value_count).max(value_count);

        group.throughput(Throughput::Elements(DEFAULT_OPS as u64));
        group.bench_function(
            BenchmarkId::new("16way_small", format!("capacity={}", capacity)),
            |b| {
                b.iter_batched(
                    || SmallCache16Way::init(adjusted_slots as u64, Options { name: "bench" }),
                    |mut cache| {
                        for i in 0..DEFAULT_OPS {
                            let value = &fixture.values[i % fixture.values.len()];
                            cache.upsert(value);
                        }
                        black_box(cache)
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_cache_upsert_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_upsert_update");
    let mut runner = TestRunner::deterministic();

    for capacity in [256usize, 16 * 1024, 256 * 1024] {
        let cache_slots = (capacity / 16) * 16;
        let actual_capacity = cache_slots.min(16 * 1024);

        let fixture = build_fixture_small(actual_capacity, &mut runner);
        let value_count = SmallCache16Way::VALUE_COUNT_MAX_MULTIPLE as usize;
        let adjusted_slots = ((cache_slots / value_count) * value_count).max(value_count);

        group.throughput(Throughput::Elements(DEFAULT_OPS as u64));
        group.bench_function(
            BenchmarkId::new("16way_small", format!("capacity={}", capacity)),
            |b| {
                b.iter_batched(
                    || {
                        let mut cache =
                            SmallCache16Way::init(adjusted_slots as u64, Options { name: "bench" });
                        // Pre-populate
                        for value in &fixture.values {
                            cache.upsert(value);
                        }
                        cache
                    },
                    |mut cache| {
                        // Update existing entries
                        for i in 0..DEFAULT_OPS {
                            let value = &fixture.values[i % fixture.values.len()];
                            cache.upsert(value);
                        }
                        black_box(cache)
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_cache_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_mixed");
    let mut runner = TestRunner::deterministic();

    for capacity in [256usize, 16 * 1024, 256 * 1024] {
        let cache_slots = (capacity / 16) * 16;
        let actual_capacity = cache_slots.min(16 * 1024);

        let fixture = build_fixture_small(actual_capacity, &mut runner);
        let value_count = SmallCache16Way::VALUE_COUNT_MAX_MULTIPLE as usize;
        let adjusted_slots = ((cache_slots / value_count) * value_count).max(value_count);

        group.throughput(Throughput::Elements(DEFAULT_OPS as u64));
        group.bench_function(
            BenchmarkId::new("80get_20upsert", format!("capacity={}", capacity)),
            |b| {
                b.iter_batched(
                    || {
                        let mut cache =
                            SmallCache16Way::init(adjusted_slots as u64, Options { name: "bench" });
                        // Pre-populate with half capacity
                        for value in fixture.values.iter().take(fixture.values.len() / 2) {
                            cache.upsert(value);
                        }
                        cache
                    },
                    |mut cache| {
                        let mut checksum = 0u64;
                        for i in 0..DEFAULT_OPS {
                            let op_type = i % 10;
                            if op_type < 8 {
                                // 80% gets
                                let key = if op_type < 4 {
                                    // 50% hit
                                    fixture.present_keys[i % fixture.present_keys.len()]
                                } else {
                                    // 50% miss
                                    fixture.absent_keys[i % fixture.absent_keys.len()]
                                };
                                if cache.get(key).is_some() {
                                    checksum = checksum.wrapping_add(1);
                                }
                            } else {
                                // 20% upserts
                                let value = &fixture.values[i % fixture.values.len()];
                                cache.upsert(value);
                            }
                        }
                        black_box(checksum)
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ---- WAYS comparison benchmarks ----

fn bench_ways_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("ways_comparison");
    let mut runner = TestRunner::deterministic();

    let capacity = 16 * 1024usize;
    let actual_capacity = 8 * 1024;
    let fixture = build_fixture_small(actual_capacity, &mut runner);

    // 16-way
    {
        let value_count = SmallCache16Way::VALUE_COUNT_MAX_MULTIPLE as usize;
        let adjusted_slots = ((capacity / value_count) * value_count).max(value_count);

        let mut cache = SmallCache16Way::init(adjusted_slots as u64, Options { name: "bench" });
        for value in &fixture.values {
            cache.upsert(value);
        }

        group.throughput(Throughput::Elements(DEFAULT_OPS as u64));
        group.bench_function("get_hit_16way", |b| {
            b.iter(|| {
                let mut hits = 0u64;
                for i in 0..DEFAULT_OPS {
                    let key = fixture.present_keys[i % fixture.present_keys.len()];
                    if cache.get(key).is_some() {
                        hits += 1;
                    }
                }
                black_box(hits)
            });
        });
    }

    // 4-way
    {
        let value_count = SmallCache4Way::VALUE_COUNT_MAX_MULTIPLE as usize;
        let adjusted_slots = ((capacity / value_count) * value_count).max(value_count);

        let mut cache = SmallCache4Way::init(adjusted_slots as u64, Options { name: "bench" });
        for value in &fixture.values {
            cache.upsert(value);
        }

        group.bench_function("get_hit_4way", |b| {
            b.iter(|| {
                let mut hits = 0u64;
                for i in 0..DEFAULT_OPS {
                    let key = fixture.present_keys[i % fixture.present_keys.len()];
                    if cache.get(key).is_some() {
                        hits += 1;
                    }
                }
                black_box(hits)
            });
        });
    }

    // 2-way
    {
        let value_count = SmallCache2Way::VALUE_COUNT_MAX_MULTIPLE as usize;
        let adjusted_slots = ((capacity / value_count) * value_count).max(value_count);

        let mut cache = SmallCache2Way::init(adjusted_slots as u64, Options { name: "bench" });
        for value in &fixture.values {
            cache.upsert(value);
        }

        group.bench_function("get_hit_2way", |b| {
            b.iter(|| {
                let mut hits = 0u64;
                for i in 0..DEFAULT_OPS {
                    let key = fixture.present_keys[i % fixture.present_keys.len()];
                    if cache.get(key).is_some() {
                        hits += 1;
                    }
                }
                black_box(hits)
            });
        });
    }

    group.finish();
}

// ---- Value size comparison ----

fn bench_value_size_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_size");
    let mut runner = TestRunner::deterministic();

    let capacity = 16 * 1024usize;

    // Small values (16B)
    {
        let actual_capacity = 8 * 1024;
        let fixture = build_fixture_small(actual_capacity, &mut runner);
        let value_count = SmallCache16Way::VALUE_COUNT_MAX_MULTIPLE as usize;
        let adjusted_slots = ((capacity / value_count) * value_count).max(value_count);

        let mut cache = SmallCache16Way::init(adjusted_slots as u64, Options { name: "bench" });
        for value in &fixture.values {
            cache.upsert(value);
        }

        group.throughput(Throughput::Elements(DEFAULT_OPS as u64));
        group.bench_function("get_hit_16B", |b| {
            b.iter(|| {
                let mut hits = 0u64;
                for i in 0..DEFAULT_OPS {
                    let key = fixture.present_keys[i % fixture.present_keys.len()];
                    if cache.get(key).is_some() {
                        hits += 1;
                    }
                }
                black_box(hits)
            });
        });
    }

    // Large values (128B)
    {
        let actual_capacity = 8 * 1024;
        let fixture = build_fixture_large(actual_capacity, &mut runner);
        let value_count = LargeCache16Way::VALUE_COUNT_MAX_MULTIPLE as usize;
        let adjusted_slots = ((capacity / value_count) * value_count).max(value_count);

        let mut cache = LargeCache16Way::init(adjusted_slots as u64, Options { name: "bench" });
        for value in &fixture.values {
            cache.upsert(value);
        }

        group.bench_function("get_hit_128B", |b| {
            b.iter(|| {
                let mut hits = 0u64;
                for i in 0..DEFAULT_OPS {
                    let key = fixture.present_keys[i % fixture.present_keys.len()];
                    if cache.get(key).is_some() {
                        hits += 1;
                    }
                }
                black_box(hits)
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_packed_array_get_set,
    bench_cache_get_hit,
    bench_cache_get_miss,
    bench_cache_upsert_insert,
    bench_cache_upsert_update,
    bench_cache_mixed_workload,
    bench_ways_comparison,
    bench_value_size_comparison,
);
criterion_main!(benches);
