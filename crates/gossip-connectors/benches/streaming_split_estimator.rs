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
//!
//! Benchmark invariants:
//! - Input stream cardinality is fixed at one million observations.
//! - Key width and file-size shape are fixed by the benchmark hook.
//! - Only `sample_cap` varies across runs.
//!
//! These constraints keep comparisons stable across commits by isolating the
//! estimator's hot-path `observe` cost from dataset-shape drift.

#[cfg(unix)]
mod unix_bench {
    use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group};
    use gossip_connectors::benchmark_streaming_split_estimator_observe_fixed_size;

    /// Unix-only Criterion group for the split estimator's fixed-size stream.
    ///
    /// The benchmark helper depends on the estimator's Unix filesystem-facing
    /// implementation details, so this module is only built where that helper
    /// exists.
    ///
    /// Benchmarks the split estimator's steady-state `observe` loop across
    /// representative sample-cap settings.
    ///
    /// The workload shape is fixed to the same one-million-item stream used by
    /// the allocation regression test so throughput and allocation regressions
    /// can be compared against the same estimator inputs over time.
    ///
    /// This benchmark varies only the estimator `sample_cap`; it does not model
    /// filesystem traversal or randomized key distributions.
    ///
    /// The measured loop always observes:
    /// - `count = 1_000_000` monotonically ordered keys.
    /// - A fixed file-size shape supplied by the helper's final argument.
    /// - One of three representative reservoir sizes: `128`, `512`, or `1024`.
    ///
    /// `black_box` is applied to both inputs and outputs so the optimizer cannot
    /// fold away the helper call and accidentally benchmark dead code.
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

#[cfg(not(unix))]
/// No-op entrypoint for non-Unix targets where the estimator benchmark hook is
/// not exported.
///
/// Keeping the bench target buildable on unsupported platforms avoids
/// conditional manifest wiring while still making the lack of estimator support
/// explicit.
fn main() {}
