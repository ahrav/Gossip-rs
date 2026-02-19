use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use gossip_stdx::RingBuffer;

const OPS_PER_ITER: u64 = 10_000;

/// Benchmarks the hot path: sustained push_back_overwrite with automatic eviction.
fn bench_push_pop_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    // Power-of-2 capacity for mask optimization
    group.bench_function("push_pop_cycle_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                rb.push_back_overwrite(black_box(i));
            }
            rb.clear();
        })
    });

    group.bench_function("push_pop_cycle_cap16", |b| {
        let mut rb: RingBuffer<u64, 16> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                rb.push_back_overwrite(black_box(i));
            }
            rb.clear();
        })
    });

    group.bench_function("push_pop_cycle_cap64", |b| {
        let mut rb: RingBuffer<u64, 64> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                rb.push_back_overwrite(black_box(i));
            }
            rb.clear();
        })
    });

    group.finish();
}

/// Alternating push/pop - tests the tightest loop.
fn bench_alternating(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("alternating_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                let _ = rb.push_back(black_box(i));
                black_box(rb.pop_front());
            }
        })
    });

    group.bench_function("alternating_cap16", |b| {
        let mut rb: RingBuffer<u64, 16> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                let _ = rb.push_back(black_box(i));
                black_box(rb.pop_front());
            }
        })
    });

    group.finish();
}

macro_rules! bench_fill_drain_cap {
    ($group:expr, $iterations:expr, $cap:literal) => {{
        $group.bench_with_input(BenchmarkId::new("fill_drain", $cap), &$cap, |b, _| {
            let mut rb: RingBuffer<u64, $cap> = RingBuffer::new();
            b.iter(|| {
                for _ in 0..$iterations {
                    for i in 0..($cap as u64) {
                        let _ = rb.push_back(black_box(i));
                    }
                    while rb.pop_front().is_some() {}
                }
            })
        });
    }};
}

/// Fill then drain - tests bulk operations.
fn bench_fill_drain(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");

    for cap in [8usize, 16, 32, 64] {
        let iterations = OPS_PER_ITER / cap as u64;
        group.throughput(Throughput::Elements(iterations * cap as u64));

        match cap {
            8 => bench_fill_drain_cap!(group, iterations, 8),
            16 => bench_fill_drain_cap!(group, iterations, 16),
            32 => bench_fill_drain_cap!(group, iterations, 32),
            64 => bench_fill_drain_cap!(group, iterations, 64),
            _ => unreachable!(),
        }
    }

    group.finish();
}

/// Test wraparound behavior - push/pop with offset head.
fn bench_wraparound(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("wraparound_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        // Pre-fill and pop to create head offset
        for i in 0..4u64 {
            let _ = rb.push_back(i);
        }
        for _ in 0..4 {
            rb.pop_front();
        }
        // Now head is at offset 4

        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                let _ = rb.push_back(black_box(i));
                black_box(rb.pop_front());
            }
        })
    });

    group.finish();
}

/// Compare push_back (with external full check) vs push_back_overwrite (integrated).
fn bench_push_variants(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("push_back_checked", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                if rb.is_full() {
                    rb.pop_front();
                }
                let _ = rb.push_back(black_box(i));
            }
            rb.clear();
        })
    });

    group.bench_function("push_back_overwrite", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                rb.push_back_overwrite(black_box(i));
            }
            rb.clear();
        })
    });

    group.finish();
}

/// Benchmark push_back_overwrite at op-log sizes (8 and 16).
fn bench_push_back_overwrite(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("push_back_overwrite_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                rb.push_back_overwrite(black_box(i));
            }
            rb.clear();
        })
    });

    group.bench_function("push_back_overwrite_cap16", |b| {
        let mut rb: RingBuffer<u64, 16> = RingBuffer::new();
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                rb.push_back_overwrite(black_box(i));
            }
            rb.clear();
        })
    });

    group.finish();
}

/// Benchmark iter().rev().find() at op-log sizes (the hot lookup path).
fn bench_iter_rev_find(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");

    group.bench_function("iter_rev_find_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        for i in 0..8u64 {
            rb.push_back(i).unwrap();
        }
        b.iter(|| {
            // Search for element 6 (near the end = found quickly in reverse).
            black_box(rb.iter().rev().find(|&&x| x == 6))
        })
    });

    group.bench_function("iter_rev_find_cap16", |b| {
        let mut rb: RingBuffer<u64, 16> = RingBuffer::new();
        for i in 0..16u64 {
            rb.push_back(i).unwrap();
        }
        b.iter(|| black_box(rb.iter().rev().find(|&&x| x == 14)))
    });

    group.finish();
}

/// Benchmark iter().rev().find() miss — worst case: exhaustive scan with no match.
fn bench_iter_rev_find_worst_case(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring_buffer");

    group.bench_function("iter_rev_find_miss_cap8", |b| {
        let mut rb: RingBuffer<u64, 8> = RingBuffer::new();
        for i in 0..8u64 {
            let _ = rb.push_back(i);
        }
        b.iter(|| {
            // 999 is not in buffer — forces full reverse scan.
            black_box(rb.iter().rev().find(|&&x| x == 999))
        })
    });

    group.bench_function("iter_rev_find_miss_cap16", |b| {
        let mut rb: RingBuffer<u64, 16> = RingBuffer::new();
        for i in 0..16u64 {
            let _ = rb.push_back(i);
        }
        b.iter(|| black_box(rb.iter().rev().find(|&&x| x == 999)))
    });

    group.finish();
}

/// Benchmark push_back_overwrite with realistic entry size (~32 bytes, matching OpLogEntry).
fn bench_push_back_overwrite_realistic(c: &mut Criterion) {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Entry([u8; 32]);

    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("overwrite_32b_cap8", |b| {
        let mut rb: RingBuffer<Entry, 8> = RingBuffer::new();
        let entry = Entry([0xAB; 32]);
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                rb.push_back_overwrite(black_box(entry));
            }
            rb.clear();
        })
    });

    group.bench_function("overwrite_32b_cap16", |b| {
        let mut rb: RingBuffer<Entry, 16> = RingBuffer::new();
        let entry = Entry([0xAB; 32]);
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                rb.push_back_overwrite(black_box(entry));
            }
            rb.clear();
        })
    });

    group.finish();
}

/// VecDeque baseline for apples-to-apples comparison with RingBuffer.
fn bench_vecdeque_baseline(c: &mut Criterion) {
    use std::collections::VecDeque;

    let mut group = c.benchmark_group("ring_buffer");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("vecdeque_overwrite_cap8", |b| {
        let mut vd = VecDeque::with_capacity(8);
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                if vd.len() == 8 {
                    vd.pop_front();
                }
                vd.push_back(black_box(i));
            }
            vd.clear();
        })
    });

    group.bench_function("vecdeque_overwrite_cap16", |b| {
        let mut vd = VecDeque::with_capacity(16);
        b.iter(|| {
            for i in 0..OPS_PER_ITER {
                if vd.len() == 16 {
                    vd.pop_front();
                }
                vd.push_back(black_box(i));
            }
            vd.clear();
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_push_pop_cycle,
    bench_alternating,
    bench_fill_drain,
    bench_wraparound,
    bench_push_variants,
    bench_push_back_overwrite,
    bench_iter_rev_find,
    bench_iter_rev_find_worst_case,
    bench_push_back_overwrite_realistic,
    bench_vecdeque_baseline,
);

criterion_main!(benches);
