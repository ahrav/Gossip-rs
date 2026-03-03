//! Benchmark: Strategy selection hint caching.
//!
//! Measures the cached code path (computes hints once and reuses them).
//!
//! Parameters: 1–3 plans, `need_count=4096`, `forward_deps=2000`, `workers=8`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use scanner_git::{bench_select_strategy, bench_synthetic_plan};

fn bench_strategy(c: &mut Criterion) {
    let mut group = c.benchmark_group("runner_exec_strategy");
    let workers = 8;
    let need_count = 4096;
    let span = 256 * 1024 * 1024;
    let forward_deps = 2000;
    let external_deps = 0;

    for &plan_count in &[1, 2, 3] {
        let plans: Vec<_> = (0..plan_count)
            .map(|i| bench_synthetic_plan(i as u16, need_count, span, forward_deps, external_deps))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("cached_hint", plan_count),
            &plans,
            |b, plans| {
                b.iter(|| black_box(bench_select_strategy(workers, plans)));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_strategy);
criterion_main!(benches);
