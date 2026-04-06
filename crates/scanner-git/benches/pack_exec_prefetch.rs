//! Criterion benchmark for OOO pack-executor software prefetch hints.
//!
//! Measures out-of-order decode over a synthetic pack with bases in the first
//! half of the pack and dependent OFS deltas in the second half. The OOO plan
//! interleaves each base with its dependent deltas, forcing non-sequential pack
//! reads that the hardware prefetcher cannot infer from address stride alone.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scanner_git::pack_exec::{
    bench_build_prefetch_case, bench_execute_prefetch_case, PackExecBenchShape,
};
use std::time::Duration;

fn bench_pack_exec_prefetch(c: &mut Criterion) {
    let ooo_case = bench_build_prefetch_case(2048, 3, PackExecBenchShape::OutOfOrder);
    let sequential_case = bench_build_prefetch_case(2048, 3, PackExecBenchShape::Sequential);

    let mut group = c.benchmark_group("pack_exec_prefetch");
    group.sample_size(200);
    group.measurement_time(Duration::from_secs(15));

    for (shape, case) in [("ooo", &ooo_case), ("sequential", &sequential_case)] {
        group.throughput(Throughput::Bytes(case.pack_bytes_len() as u64));
        for lookahead in [0usize, 2, 4, 8] {
            group.bench_with_input(
                BenchmarkId::new(shape, format!("k{lookahead}")),
                &lookahead,
                |b, &lookahead| {
                    b.iter(|| {
                        black_box(
                            bench_execute_prefetch_case(case, lookahead).expect("pack exec bench"),
                        )
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_pack_exec_prefetch);
criterion_main!(benches);
