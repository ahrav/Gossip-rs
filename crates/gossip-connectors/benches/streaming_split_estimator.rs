//! Criterion harness for the streaming split estimator's fixed-size `observe`
//! loop.
//!
//! This uses the same doc-hidden hook as the allocation regression test so
//! throughput and heap-traffic checks stay aligned: both cover monotonically
//! ordered fixed-width keys with a uniform file size, without filesystem walk
//! noise or randomized workload generation.
//!
//! The benchmark hook is only exported on Unix (the split estimator depends on
//! Unix filesystem APIs), so this file compiles as a no-op on other platforms.

#[cfg(unix)]
mod unix_bench {
    use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group};
    use gossip_connectors::benchmark_streaming_split_estimator_observe_fixed_size;

    /// Benchmarks the split estimator's steady-state `observe` loop across
    /// representative sample-cap settings.
    ///
    /// The workload shape is fixed to the same one-million-item stream used by
    /// the allocation regression test so throughput and allocation regressions
    /// can be compared against the same estimator inputs over time.
    pub fn bench_observe(c: &mut Criterion) {
        let mut group = c.benchmark_group("streaming_split_estimator_observe");
        // Keep the benchmark's stream shape pinned to the allocation guard so
        // changes in throughput can be evaluated against the same workload.
        let count = 1_000_000usize;

        // Thirty samples keeps CI runtime bounded while still giving enough
        // signal to catch moderate regressions in this hot loop.
        group.sample_size(30);
        group.throughput(Throughput::Elements(count as u64));

        for &sample_cap in &[128usize, 512, 1024] {
            group.bench_with_input(
                BenchmarkId::from_parameter(sample_cap),
                &sample_cap,
                |b, &sample_cap| {
                    b.iter(|| {
                        // Black-box both inputs and outputs so the optimizer
                        // cannot elide the estimator work we are timing.
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
}

#[cfg(unix)]
criterion::criterion_main!(unix_bench::benches);

// On non-Unix platforms the estimator (and its benchmark hook) is unavailable,
// so the bench binary compiles but does nothing.
#[cfg(not(unix))]
fn main() {}
