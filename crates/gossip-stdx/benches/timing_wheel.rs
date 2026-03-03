//! Benchmarks for TimingWheel and Bitset2.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use gossip_stdx::{Bitset2, TimingWheel};

const OPS_PER_ITER: u64 = 10_000;

// ============================================================================
// Bitset2 Benchmarks
// ============================================================================

fn bench_bitset_set_clear(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitset2/set_clear");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    for bits in [64, 512, 4096, 65536] {
        group.bench_with_input(BenchmarkId::new("set", bits), &bits, |b, &bits| {
            let mut bs = Bitset2::new(bits);
            b.iter(|| {
                for i in 0..OPS_PER_ITER as usize {
                    bs.set(black_box(i % bits));
                }
                // Reset for next iteration
                for i in 0..bits {
                    bs.clear(i);
                }
            })
        });

        group.bench_with_input(BenchmarkId::new("clear", bits), &bits, |b, &bits| {
            let mut bs = Bitset2::new(bits);
            // Pre-set all bits
            for i in 0..bits {
                bs.set(i);
            }
            b.iter(|| {
                // Clear and re-set in alternating pattern
                for i in 0..OPS_PER_ITER as usize {
                    let idx = i % bits;
                    bs.clear(black_box(idx));
                    bs.set(idx);
                }
            })
        });
    }

    group.finish();
}

fn bench_bitset_find_next_set_ge(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitset2/find_next_set_ge");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Test different densities
    for (name, density) in [
        ("sparse_1pct", 0.01),
        ("moderate_25pct", 0.25),
        ("dense_75pct", 0.75),
    ] {
        for bits in [512, 4096, 65536] {
            let label = format!("{}/{}", name, bits);
            group.bench_function(&label, |b| {
                let mut bs = Bitset2::new(bits);
                // Set bits according to density
                let step = (1.0 / density) as usize;
                for i in (0..bits).step_by(step.max(1)) {
                    bs.set(i);
                }

                b.iter(|| {
                    let mut sum = 0usize;
                    for i in 0..OPS_PER_ITER as usize {
                        let from = i % bits;
                        if let Some(found) = bs.find_next_set_ge(black_box(from)) {
                            sum = sum.wrapping_add(found);
                        }
                    }
                    black_box(sum)
                })
            });
        }
    }

    group.finish();
}

fn bench_bitset_find_next_set_cyclic(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitset2/find_next_set_cyclic");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    for bits in [512, 4096, 65536] {
        // 25% density for cyclic test
        group.bench_with_input(BenchmarkId::new("moderate", bits), &bits, |b, &bits| {
            let mut bs = Bitset2::new(bits);
            for i in (0..bits).step_by(4) {
                bs.set(i);
            }

            b.iter(|| {
                let mut sum = 0usize;
                for i in 0..OPS_PER_ITER as usize {
                    let from = i % bits;
                    if let Some(found) = bs.find_next_set_cyclic(black_box(from)) {
                        sum = sum.wrapping_add(found);
                    }
                }
                black_box(sum)
            })
        });
    }

    group.finish();
}

// ============================================================================
// TimingWheel Benchmarks
// ============================================================================

#[derive(Clone, Copy, Debug)]
struct Payload {
    hi_end: u64,
    id: u32,
}

fn bench_timing_wheel_push(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing_wheel/push");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Test different granularities
    for (g_name, horizon, cap) in [
        ("g1_small", 256u64, 1024usize),
        ("g8_medium", 1024u64, 4096usize),
        ("g64_large", 8192u64, 16384usize),
    ] {
        group.bench_function(g_name, |b| match g_name {
            "g1_small" => {
                let mut tw: TimingWheel<Payload, 1> = TimingWheel::new(horizon, cap);
                let mut now = 0u64;
                b.iter(|| {
                    for i in 0..OPS_PER_ITER {
                        let hi_end = now + (i % horizon);
                        let _ = tw.push(
                            black_box(hi_end),
                            Payload {
                                hi_end,
                                id: i as u32,
                            },
                        );
                    }
                    // Drain all to reset
                    now += horizon + 1;
                    tw.advance_and_drain(now, |_| {});
                })
            }
            "g8_medium" => {
                let mut tw: TimingWheel<Payload, 8> = TimingWheel::new(horizon, cap);
                let mut now = 0u64;
                b.iter(|| {
                    for i in 0..OPS_PER_ITER {
                        let hi_end = now + (i % horizon);
                        let _ = tw.push(
                            black_box(hi_end),
                            Payload {
                                hi_end,
                                id: i as u32,
                            },
                        );
                    }
                    now += horizon + 1;
                    tw.advance_and_drain(now, |_| {});
                })
            }
            "g64_large" => {
                let mut tw: TimingWheel<Payload, 64> = TimingWheel::new(horizon, cap);
                let mut now = 0u64;
                b.iter(|| {
                    for i in 0..OPS_PER_ITER {
                        let hi_end = now + (i % horizon);
                        let _ = tw.push(
                            black_box(hi_end),
                            Payload {
                                hi_end,
                                id: i as u32,
                            },
                        );
                    }
                    now += horizon + 1;
                    tw.advance_and_drain(now, |_| {});
                })
            }
            _ => unreachable!(),
        });
    }

    group.finish();
}

fn bench_timing_wheel_advance_drain(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing_wheel/advance_drain");

    // Test draining different numbers of buckets
    for (name, buckets_to_drain, items_per_bucket) in [
        ("few_buckets", 8, 10),
        ("many_buckets", 64, 5),
        ("dense_buckets", 32, 20),
    ] {
        let total_items = buckets_to_drain * items_per_bucket;
        group.throughput(Throughput::Elements(total_items as u64));

        group.bench_function(name, |b| {
            let horizon = 1024u64;
            let cap = (total_items + 256) as usize;
            let mut tw: TimingWheel<Payload, 8> = TimingWheel::new(horizon, cap);

            b.iter(|| {
                // Pre-fill the wheel
                for bucket in 0..buckets_to_drain {
                    for item in 0..items_per_bucket {
                        let hi_end = ((bucket + 1) * 8) as u64; // Each bucket = 8 bytes with G=8
                        let id = (bucket * items_per_bucket + item) as u32;
                        let _ = tw.push(hi_end, Payload { hi_end, id });
                    }
                }

                // Drain all at once
                let mut count = 0usize;
                tw.advance_and_drain(black_box((buckets_to_drain * 8) as u64), |payload| {
                    black_box(payload.hi_end);
                    black_box(payload.id);
                    count += 1;
                });
                black_box(count)
            })
        });
    }

    group.finish();
}

fn bench_timing_wheel_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing_wheel/mixed");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Simulates real usage: interleaved push and advance
    group.bench_function("push_advance_interleaved", |b| {
        let horizon = 512u64;
        let cap = 2048usize;
        let mut tw: TimingWheel<Payload, 8> = TimingWheel::new(horizon, cap);
        let mut now = 0u64;
        let mut next_id = 0u32;

        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                // Push 3 items
                for _ in 0..3 {
                    let hi_end = now + (next_id as u64 % horizon);
                    let _ = tw.push(
                        hi_end,
                        Payload {
                            hi_end,
                            id: next_id,
                        },
                    );
                    next_id = next_id.wrapping_add(1);
                }

                // Advance time by a small amount
                now += 8;
                tw.advance_and_drain(black_box(now), |payload| {
                    black_box(payload.hi_end);
                    black_box(payload.id);
                });
            }

            // Final drain
            now += horizon + 1;
            tw.advance_and_drain(now, |payload| {
                black_box(payload.hi_end);
                black_box(payload.id);
            });
        })
    });

    // Burst push followed by drain
    group.bench_function("burst_push_then_drain", |b| {
        let horizon = 1024u64;
        let cap = 8192usize;
        let mut tw: TimingWheel<Payload, 8> = TimingWheel::new(horizon, cap);
        let mut now = 0u64;

        b.iter(|| {
            // Burst push
            for i in 0..OPS_PER_ITER {
                let hi_end = now + (i % horizon);
                let _ = tw.push(
                    black_box(hi_end),
                    Payload {
                        hi_end,
                        id: i as u32,
                    },
                );
            }

            // Single big drain
            now += horizon + 1;
            let mut drained = 0usize;
            tw.advance_and_drain(black_box(now), |payload| {
                black_box(payload.hi_end);
                black_box(payload.id);
                drained += 1;
            });
            black_box(drained)
        })
    });

    group.finish();
}

fn bench_timing_wheel_reset(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing_wheel/reset");

    for item_count in [100, 1000, 5000, 10000] {
        group.throughput(Throughput::Elements(item_count as u64));

        group.bench_with_input(
            BenchmarkId::new("items", item_count),
            &item_count,
            |b, &count| {
                let horizon = 8192u64;
                let cap = (count + 1024) as usize;
                let mut tw: TimingWheel<Payload, 8> = TimingWheel::new(horizon, cap);

                b.iter(|| {
                    // Fill the wheel
                    for i in 0..count {
                        let hi_end = (i as u64 % horizon) + 1;
                        let _ = tw.push(
                            hi_end,
                            Payload {
                                hi_end,
                                id: i as u32,
                            },
                        );
                    }
                    // Reset
                    tw.reset();
                })
            },
        );
    }

    group.finish();
}

fn bench_timing_wheel_granularity_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing_wheel/granularity");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Compare different granularity values for the same workload
    let horizon = 1024u64;
    let cap = 4096usize;

    group.bench_function("g1_exact", |b| {
        let mut tw: TimingWheel<Payload, 1> = TimingWheel::new(horizon, cap);
        let mut now = 0u64;

        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                let hi_end = now + (i % horizon);
                let _ = tw.push(
                    black_box(hi_end),
                    Payload {
                        hi_end,
                        id: i as u32,
                    },
                );
            }
            now += horizon + 1;
            tw.advance_and_drain(now, |payload| {
                black_box(payload.hi_end);
                black_box(payload.id);
            });
        })
    });

    group.bench_function("g8_coarse", |b| {
        let mut tw: TimingWheel<Payload, 8> = TimingWheel::new(horizon, cap);
        let mut now = 0u64;

        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                let hi_end = now + (i % horizon);
                let _ = tw.push(
                    black_box(hi_end),
                    Payload {
                        hi_end,
                        id: i as u32,
                    },
                );
            }
            now += horizon + 1;
            tw.advance_and_drain(now, |payload| {
                black_box(payload.hi_end);
                black_box(payload.id);
            });
        })
    });

    group.bench_function("g64_very_coarse", |b| {
        let mut tw: TimingWheel<Payload, 64> = TimingWheel::new(horizon, cap);
        let mut now = 0u64;

        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                let hi_end = now + (i % horizon);
                let _ = tw.push(
                    black_box(hi_end),
                    Payload {
                        hi_end,
                        id: i as u32,
                    },
                );
            }
            now += horizon + 1;
            tw.advance_and_drain(now, |payload| {
                black_box(payload.hi_end);
                black_box(payload.id);
            });
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_bitset_set_clear,
    bench_bitset_find_next_set_ge,
    bench_bitset_find_next_set_cyclic,
    bench_timing_wheel_push,
    bench_timing_wheel_advance_drain,
    bench_timing_wheel_mixed_workload,
    bench_timing_wheel_reset,
    bench_timing_wheel_granularity_comparison,
);

criterion_main!(benches);
