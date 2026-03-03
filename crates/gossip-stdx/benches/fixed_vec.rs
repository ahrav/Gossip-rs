//! Benchmarks for InlineVec<T, N>.
//!
//! These benchmarks measure the hot-path performance of InlineVec as used for DecodeSteps:
//! - Fixed capacity N=8
//! - Element type similar to DecodeStep (~24-32 bytes with Range<usize>)
//! - Write-once (new + extend_from_slice), read-many (iteration via Deref)

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use gossip_stdx::InlineVec;
use std::ops::Range;

// Simulate DecodeStep structure for realistic benchmarks.
// The real DecodeStep is an enum with variants containing usize and Range<usize>.
// Range<usize> is Clone but not Copy, matching the real DecodeStep.
#[derive(Clone, Debug)]
#[repr(C)]
struct FakeDecodeStep {
    transform_idx: usize,
    parent_span: Range<usize>,
}

impl FakeDecodeStep {
    fn new(idx: usize) -> Self {
        Self {
            transform_idx: idx,
            parent_span: idx..idx + 100,
        }
    }
}

// Type alias matching the real DecodeSteps = InlineVec<DecodeStep, 8>
type DecodeSteps = InlineVec<FakeDecodeStep, 8>;

// ============================================================================
// 1. Construction Benchmarks
// ============================================================================

fn bench_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_vec/construction");

    group.bench_function("new_n8", |b| {
        b.iter(|| {
            let v: DecodeSteps = InlineVec::new();
            black_box(v)
        })
    });

    group.bench_function("default_n8", |b| {
        b.iter(|| {
            let v: DecodeSteps = InlineVec::default();
            black_box(v)
        })
    });

    group.finish();
}

// ============================================================================
// 2. Extend from Slice Benchmarks (PRIMARY HOT PATH)
// ============================================================================

fn bench_extend_from_slice(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_vec/extend_from_slice");

    // Various slice sizes matching real-world usage
    for n in [1, 2, 4, 8] {
        let steps: Vec<_> = (0..n).map(FakeDecodeStep::new).collect();
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("elements", n), &steps, |b, steps| {
            b.iter(|| {
                let mut v: DecodeSteps = InlineVec::new();
                v.extend_from_slice(black_box(steps.as_slice()));
                black_box(&v);
            })
        });
    }

    group.finish();
}

// ============================================================================
// 3. Iteration Benchmarks
// ============================================================================

fn bench_iteration(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_vec/iteration");
    group.throughput(Throughput::Elements(8));

    let steps: Vec<_> = (0..8).map(FakeDecodeStep::new).collect();
    let mut v: DecodeSteps = InlineVec::new();
    v.extend_from_slice(&steps);

    // Iterate via Deref (as_slice)
    group.bench_function("iterate_n8", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for step in v.iter() {
                sum = sum.wrapping_add(step.transform_idx);
            }
            black_box(sum)
        })
    });

    // Index access via Deref
    group.bench_function("index_access_n8", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            let slice = v.as_slice();
            for item in slice {
                sum = sum.wrapping_add(item.transform_idx);
            }
            black_box(sum)
        })
    });

    group.finish();
}

// ============================================================================
// 4. Real-World Workflow Benchmarks
// ============================================================================

fn bench_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_vec/workflow");

    // Simulate drain_findings_materialized hot path:
    // new() -> extend_from_slice() -> iterate
    for n in [4, 8] {
        let steps: Vec<_> = (0..n).map(FakeDecodeStep::new).collect();
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(
            BenchmarkId::new("new_extend_iterate", n),
            &steps,
            |b, steps| {
                b.iter(|| {
                    let mut v: DecodeSteps = InlineVec::new();
                    v.extend_from_slice(black_box(steps.as_slice()));
                    let mut sum = 0usize;
                    for step in v.iter() {
                        sum = sum.wrapping_add(step.transform_idx);
                    }
                    black_box(sum)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 5. Clone Benchmarks
// ============================================================================

fn bench_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_vec/clone");

    for n in [4, 8] {
        let steps: Vec<_> = (0..n).map(FakeDecodeStep::new).collect();
        let mut v: DecodeSteps = InlineVec::new();
        v.extend_from_slice(&steps);

        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("elements", n), &v, |b, v| {
            b.iter(|| black_box(v.clone()))
        });
    }

    group.finish();
}

// ============================================================================
// 6. Comparison vs Vec<T>
// ============================================================================

fn bench_vs_vec(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_vec/vs_vec");
    group.throughput(Throughput::Elements(8));

    let steps: Vec<_> = (0..8).map(FakeDecodeStep::new).collect();

    // InlineVec workflow
    group.bench_function("fixedvec_workflow", |b| {
        b.iter(|| {
            let mut v: DecodeSteps = InlineVec::new();
            v.extend_from_slice(black_box(steps.as_slice()));
            let mut sum = 0usize;
            for step in v.iter() {
                sum = sum.wrapping_add(step.transform_idx);
            }
            black_box(sum)
        })
    });

    // Vec with_capacity workflow
    group.bench_function("vec_with_capacity_workflow", |b| {
        b.iter(|| {
            let mut v: Vec<FakeDecodeStep> = Vec::with_capacity(8);
            v.extend_from_slice(black_box(steps.as_slice()));
            let mut sum = 0usize;
            for step in v.iter() {
                sum = sum.wrapping_add(step.transform_idx);
            }
            black_box(sum)
        })
    });

    // Vec default workflow (measures allocation overhead)
    group.bench_function("vec_default_workflow", |b| {
        b.iter(|| {
            let mut v: Vec<FakeDecodeStep> = Vec::new();
            v.extend_from_slice(black_box(steps.as_slice()));
            let mut sum = 0usize;
            for step in v.iter() {
                sum = sum.wrapping_add(step.transform_idx);
            }
            black_box(sum)
        })
    });

    group.finish();
}

// ============================================================================
// 7. Batch Workflow (Multiple Findings Simulation)
// ============================================================================

fn bench_batch_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("fixed_vec/batch");

    // Simulate processing multiple findings in a batch
    let batch_sizes = [10, 100, 1000];
    let steps: Vec<_> = (0..4).map(FakeDecodeStep::new).collect();

    for &batch_size in &batch_sizes {
        group.throughput(Throughput::Elements(batch_size as u64 * 4));

        group.bench_with_input(
            BenchmarkId::new("findings", batch_size),
            &batch_size,
            |b, &batch_size| {
                b.iter(|| {
                    let mut total = 0usize;
                    for _ in 0..batch_size {
                        let mut v: DecodeSteps = InlineVec::new();
                        v.extend_from_slice(black_box(steps.as_slice()));
                        for step in v.iter() {
                            total = total.wrapping_add(step.transform_idx);
                        }
                    }
                    black_box(total)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_construction,
    bench_extend_from_slice,
    bench_iteration,
    bench_workflow,
    bench_clone,
    bench_vs_vec,
    bench_batch_workflow,
);

criterion_main!(benches);
