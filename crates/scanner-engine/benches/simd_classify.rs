//! Criterion benchmarks for SIMD-accelerated byte classification.
//!
//! Measures throughput of `classify_window` across a range of input sizes to
//! quantify the SIMD (NEON / SSE2) advantage over scalar fallback. The input
//! cycles through all four ASCII classes (lowercase, uppercase, digit, special)
//! to exercise every classification branch.
//!
//! ## Running
//!
//! ```sh
//! cargo bench --bench simd_classify --features bench
//! ```

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use scanner_engine::bench_classify_window;
use std::time::Duration;

fn bench_classify(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_classify_window");
    group.sample_size(50);
    group.measurement_time(Duration::from_secs(3));

    for &size in &[64, 256, 1024, 4096, 16384] {
        // Realistic mixed-class distribution: cycling through all four classes.
        let input: Vec<u8> = [b'a', b'A', b'0', b'!']
            .iter()
            .copied()
            .cycle()
            .take(size)
            .collect();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{}_bytes", size), |b| {
            b.iter(|| black_box(bench_classify_window(black_box(&input))))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_classify);
criterion_main!(benches);
