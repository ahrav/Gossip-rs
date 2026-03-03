use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use scanner_engine::BenchHitAccPool;

struct XorShift64(u64);
impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn bench_push_span(c: &mut Criterion) {
    let mut group = c.benchmark_group("hit_pool_push_span");

    for &(pair_count, max_hits, label) in &[
        (30, 8, "small_30x8"),
        (300, 256, "medium_300x256"),
        (3000, 256, "large_3000x256"),
    ] {
        // Sparse: 5% of pairs touched, 4 hits each
        let touched_count = (pair_count * 5 / 100).max(1);
        let hits_per_pair = 4usize;
        let total_ops = touched_count * hits_per_pair;

        let mut rng = XorShift64::new(0xdead_beef);
        let pairs: Vec<usize> = (0..total_ops)
            .map(|_| (rng.next() as usize % touched_count) * (pair_count / touched_count))
            .collect();
        let starts: Vec<u32> = (0..total_ops).map(|i| (i * 100) as u32).collect();
        let ends: Vec<u32> = starts.iter().map(|s| s + 200).collect();

        group.bench_function(BenchmarkId::new("sparse", label), |b| {
            let mut pool = BenchHitAccPool::new(pair_count, max_hits);
            b.iter(|| {
                for i in 0..total_ops {
                    pool.push(black_box(pairs[i]), starts[i], ends[i], starts[i]);
                }
                pool.reset();
            })
        });

        // Dense: 80% of pairs touched, 4 hits each
        let touched_count_dense = pair_count * 80 / 100;
        let total_ops_dense = touched_count_dense * hits_per_pair;
        let pairs_dense: Vec<usize> = (0..total_ops_dense)
            .map(|i| i / hits_per_pair % pair_count)
            .collect();
        let starts_dense: Vec<u32> = (0..total_ops_dense).map(|i| (i * 50) as u32).collect();
        let ends_dense: Vec<u32> = starts_dense.iter().map(|s| s + 200).collect();

        group.bench_function(BenchmarkId::new("dense", label), |b| {
            let mut pool = BenchHitAccPool::new(pair_count, max_hits);
            b.iter(|| {
                for i in 0..total_ops_dense {
                    pool.push(
                        black_box(pairs_dense[i]),
                        starts_dense[i],
                        ends_dense[i],
                        starts_dense[i],
                    );
                }
                pool.reset();
            })
        });
    }
    group.finish();
}

fn bench_take_into(c: &mut Criterion) {
    let pair_count = 300;
    let max_hits = 256;
    let hits_per_pair = 8;
    let touched_count = 60; // 20% of pairs

    let mut group = c.benchmark_group("hit_pool_take_into");
    group.bench_function("take_60_pairs_8_hits", |b| {
        let mut pool = BenchHitAccPool::new(pair_count, max_hits);
        b.iter(|| {
            // Push phase
            for p in 0..touched_count {
                let pair = p * (pair_count / touched_count);
                for h in 0..hits_per_pair {
                    pool.push(
                        pair,
                        (h * 100) as u32,
                        (h * 100 + 200) as u32,
                        (h * 100) as u32,
                    );
                }
            }
            // Take phase
            for p in 0..touched_count {
                let pair = p * (pair_count / touched_count);
                black_box(pool.take(pair));
            }
            pool.reset();
        })
    });
    group.finish();
}

fn bench_push_overflow(c: &mut Criterion) {
    let pair_count = 100;
    let max_hits = 8;

    let mut group = c.benchmark_group("hit_pool_overflow");
    group.bench_function("push_16_hits_cap_8", |b| {
        let mut pool = BenchHitAccPool::new(pair_count, max_hits);
        b.iter(|| {
            // Push 16 hits to pair 0 — triggers overflow at hit 9
            for h in 0..16 {
                pool.push(
                    black_box(0),
                    (h * 100) as u32,
                    (h * 100 + 200) as u32,
                    (h * 100) as u32,
                );
            }
            pool.reset();
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_push_span,
    bench_take_into,
    bench_push_overflow
);
criterion_main!(benches);
