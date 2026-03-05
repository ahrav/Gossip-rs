//! Criterion harness for the streaming split estimator's fixed-size `observe`
//! loop.
//!
//! This uses the same doc-hidden hook as the allocation regression test so
//! throughput and heap-traffic checks stay aligned: both cover monotonically
//! ordered fixed-width keys with a uniform file size, without filesystem walk
//! noise or randomized workload generation.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use gossip_connectors::benchmark_streaming_split_estimator_observe_fixed_size;

/// Measure steady-state `observe` cost across sample-cap settings.
fn bench_observe(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_split_estimator_observe");
    // Match the perf regression test's 1M-item workload so throughput numbers
    // can be compared against the allocation guard on the same stream shape.
    let count = 1_000_000usize;

    group.sample_size(10);
    group.throughput(Throughput::Elements(count as u64));

    for &sample_cap in &[128usize, 512, 1024] {
        group.bench_with_input(
            BenchmarkId::from_parameter(sample_cap),
            &sample_cap,
            |b, &sample_cap| {
                b.iter(|| {
                    black_box(benchmark_streaming_split_estimator_observe_fixed_size(
                        black_box(sample_cap),
                        black_box(count),
                        black_box(1),
                    ))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_observe);
criterion_main!(benches);
