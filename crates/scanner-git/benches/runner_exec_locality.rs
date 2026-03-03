//! Benchmark: Locality estimation allocation — hoisted Vec alloc.
//!
//! Measures the hoisted code path (`build_exec_pos_by_need` hoisted outside
//! the loop so the allocation happens once).
//!
//! Parameters: `need_count` ∈ {1024, 8192, 32768}, `dep_gap=4`, `cap=16`.
//! With `MAX_SHARDS_WITH_DEP_PRESSURE=2`, cap=16 forces ~14 loop iterations,
//! each touching all deps — making the allocation cost visible.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use scanner_git::{bench_apply_locality_shard_cap, bench_synthetic_locality_plan};

fn bench_locality(c: &mut Criterion) {
    let mut group = c.benchmark_group("runner_exec_locality");
    let dep_gap = 4;
    let shard_cap = 16;

    for &need_count in &[1024, 8192, 32768] {
        let plan = bench_synthetic_locality_plan(need_count, dep_gap);

        group.bench_with_input(
            BenchmarkId::new("hoisted_alloc", need_count),
            &plan,
            |b, plan| {
                b.iter(|| black_box(bench_apply_locality_shard_cap(plan, shard_cap)));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_locality);
criterion_main!(benches);
