//! Commit graph generation scaling benchmarks.
//!
//! Focuses on `CommitGraphMem::build` for synthetic graph shapes that
//! historically stress generation assignment:
//! - long linear chains
//! - deep/wide layered DAGs
//!
//! Usage:
//! `cargo bench --bench commit_graph_generation`

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use scanner_git::{CommitGraphMem, LoadedCommit, ObjectFormat, OidBytes};

fn oid_from_u64(value: u64) -> OidBytes {
    let mut bytes = [0u8; 20];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    OidBytes::sha1(bytes)
}

fn make_commit(id: u64, parents: &[u64]) -> LoadedCommit {
    LoadedCommit {
        oid: oid_from_u64(id),
        tree_oid: oid_from_u64(id ^ 0xAA55_AA55_AA55_AA55),
        parents: parents.iter().map(|p| oid_from_u64(*p)).collect(),
        timestamp: id,
    }
}

fn linear_chain(count: usize) -> Vec<LoadedCommit> {
    let mut commits = Vec::with_capacity(count);
    for idx in 0..count as u64 {
        let parents = if idx == 0 { vec![] } else { vec![idx - 1] };
        commits.push(make_commit(idx, &parents));
    }
    // Feed commits in reverse topological order to avoid accidental best-case input.
    commits.reverse();
    commits
}

fn layered_dag(depth: usize, width: usize) -> Vec<LoadedCommit> {
    let mut commits = Vec::with_capacity(depth * width);
    for layer in 0..depth as u64 {
        for col in 0..width as u64 {
            let id = layer * width as u64 + col;
            let parents = if layer == 0 {
                vec![]
            } else {
                let prev = (layer - 1) * width as u64;
                vec![prev + col, prev + ((col + 1) % width as u64)]
            };
            commits.push(make_commit(id, &parents));
        }
    }
    commits.reverse();
    commits
}

fn bench_linear_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_graph_generation/linear_chain");
    group.sample_size(20);

    for count in [1_024usize, 4_096, 16_384, 32_768] {
        let commits = linear_chain(count);
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &commits,
            |b, commits| {
                b.iter_batched(
                    || commits.clone(),
                    |input| {
                        let graph = CommitGraphMem::build(black_box(input), ObjectFormat::Sha1)
                            .expect("commit graph build should succeed");
                        black_box(graph);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_layered_dag(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_graph_generation/layered_dag");
    group.sample_size(20);

    for (depth, width) in [(64usize, 32usize), (128, 64), (256, 64)] {
        let count = depth * width;
        let commits = layered_dag(depth, width);
        group.throughput(Throughput::Elements(count as u64));
        let label = format!("d{depth}_w{width}_n{count}");
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &commits,
            |b, commits| {
                b.iter_batched(
                    || commits.clone(),
                    |input| {
                        let graph = CommitGraphMem::build(black_box(input), ObjectFormat::Sha1)
                            .expect("commit graph build should succeed");
                        black_box(graph);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_linear_chain, bench_layered_dag);
criterion_main!(benches);
