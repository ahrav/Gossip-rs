use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use gossip_stdx::InlineVec;

const OPS_PER_ITER: u64 = 10_000;

/// The 99% case: push 1–2 elements into an inline vec.
fn bench_push_small(c: &mut Criterion) {
    let mut group = c.benchmark_group("inline_vec");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("push_1_elem", |b| {
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let mut v = InlineVec::<u32, 8>::new();
                v.push(black_box(42));
                black_box(&v);
            }
        })
    });

    group.bench_function("push_2_elems", |b| {
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let mut v = InlineVec::<u32, 8>::new();
                v.push(black_box(1));
                v.push(black_box(2));
                black_box(&v);
            }
        })
    });

    group.finish();
}

/// Hot path pattern from session.rs: from_slice + push.
fn bench_from_slice_then_push(c: &mut Criterion) {
    let mut group = c.benchmark_group("inline_vec");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("from_slice_2_then_push", |b| {
        let data = [1u32, 2];
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let mut v = InlineVec::<u32, 8>::from_slice(black_box(&data));
                v.push(black_box(3));
                black_box(&v);
            }
        })
    });

    group.bench_function("from_slice_8_exact", |b| {
        let data = [1u32, 2, 3, 4, 5, 6, 7, 8];
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let v = InlineVec::<u32, 8>::from_slice(black_box(&data));
                black_box(&v);
            }
        })
    });

    group.finish();
}

/// Batch extend: measures the optimized single-check fast path.
fn bench_extend_from_slice(c: &mut Criterion) {
    let mut group = c.benchmark_group("inline_vec");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("extend_3_elems_fits_inline", |b| {
        let ext = [10u32, 20, 30];
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let mut v = InlineVec::<u32, 8>::new();
                v.push(black_box(1));
                v.extend_from_slice(black_box(&ext));
                black_box(&v);
            }
        })
    });

    group.bench_function("extend_5_elems_fits_inline", |b| {
        let ext = [10u32, 20, 30, 40, 50];
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let mut v = InlineVec::<u32, 8>::new();
                v.extend_from_slice(black_box(&ext));
                black_box(&v);
            }
        })
    });

    group.finish();
}

/// Cold path: push N+1 elements to trigger spill.
fn bench_spill(c: &mut Criterion) {
    let mut group = c.benchmark_group("inline_vec");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("spill_at_9_cap8", |b| {
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let mut v = InlineVec::<u32, 8>::new();
                for i in 0..9u32 {
                    v.push(black_box(i));
                }
                black_box(&v);
            }
        })
    });

    group.finish();
}

/// Read path: as_slice on inline vs heap.
fn bench_as_slice(c: &mut Criterion) {
    let mut group = c.benchmark_group("inline_vec");

    let mut inline = InlineVec::<u32, 8>::new();
    for i in 0..4 {
        inline.push(i);
    }

    let mut heap = InlineVec::<u32, 4>::new();
    for i in 0..5 {
        heap.push(i);
    }

    group.bench_function("as_slice_inline_4", |b| {
        b.iter(|| black_box(inline.as_slice()))
    });

    group.bench_function("as_slice_heap_5", |b| b.iter(|| black_box(heap.as_slice())));

    group.finish();
}

/// Vec baseline for apples-to-apples comparison.
fn bench_vec_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("inline_vec");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    #[allow(clippy::vec_init_then_push)]
    group.bench_function("vec_push_2_elems", |b| {
        // Deliberately not using vec![] — we want to measure per-push
        // allocation behavior to compare against InlineVec.
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let mut v = Vec::new();
                v.push(black_box(1u32));
                v.push(black_box(2u32));
                black_box(&v);
            }
        })
    });

    group.bench_function("vec_from_slice_2_then_push", |b| {
        let data = [1u32, 2];
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let mut v = data.to_vec();
                v.push(black_box(3));
                black_box(&v);
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_push_small,
    bench_from_slice_then_push,
    bench_extend_from_slice,
    bench_spill,
    bench_as_slice,
    bench_vec_baseline,
);

criterion_main!(benches);
