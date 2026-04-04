//! Commit-plan watermark validation benchmarks.
//!
//! Exercises `CommitPlanIter` startup for the three watermark states that
//! matter for ref initialization:
//! - matching watermark generation (ancestry walk still required),
//! - stale generation mismatch (force-push fast path),
//! - missing watermark.

use std::collections::HashMap;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use gix_commitgraph::Position;
use scanner_git::{
    ByteRef, CommitGraph, CommitPlanError, CommitPlanIter, CommitWalkLimits, OidBytes,
    ParentScratch, RefWatermark, StartSetRef,
};

struct BenchGraph {
    oids: Vec<OidBytes>,
    lookup: HashMap<OidBytes, Position>,
    generations: Vec<u32>,
}

impl BenchGraph {
    fn linear(count: u32) -> Self {
        let mut oids = Vec::with_capacity(count as usize);
        let mut lookup = HashMap::with_capacity(count as usize);
        let mut generations = Vec::with_capacity(count as usize);

        for idx in 0..count {
            let oid = oid_from_u32(idx);
            let pos = Position(idx);
            oids.push(oid);
            lookup.insert(oid, pos);
            generations.push(idx + 1);
        }

        Self {
            oids,
            lookup,
            generations,
        }
    }

    fn oid(&self, pos: Position) -> OidBytes {
        self.oids[pos.0 as usize]
    }
}

impl CommitGraph for BenchGraph {
    fn num_commits(&self) -> u32 {
        self.oids.len() as u32
    }

    fn lookup(&self, oid: &OidBytes) -> Result<Option<Position>, CommitPlanError> {
        Ok(self.lookup.get(oid).copied())
    }

    fn generation(&self, pos: Position) -> u32 {
        self.generations[pos.0 as usize]
    }

    fn collect_parents(
        &self,
        pos: Position,
        max_parents: u32,
        scratch: &mut ParentScratch,
    ) -> Result<(), CommitPlanError> {
        scratch.clear();
        if pos.0 > 0 {
            scratch.push(Position(pos.0 - 1), max_parents)?;
        }
        Ok(())
    }

    fn root_tree_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
        Ok(self.oid(pos))
    }

    fn commit_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
        Ok(self.oid(pos))
    }

    fn committer_timestamp(&self, pos: Position) -> u64 {
        u64::from(pos.0)
    }
}

fn oid_from_u32(value: u32) -> OidBytes {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&value.to_be_bytes());
    OidBytes::sha1(bytes)
}

fn benchmark_commit_walk_watermarks(c: &mut Criterion) {
    let graph = BenchGraph::linear(65_536);
    let tip_pos = Position(65_535);
    let watermark_pos = Position(32_768);
    let limits = CommitWalkLimits::DEFAULT;
    let cases = [
        (
            "ancestor_match",
            Some(RefWatermark {
                oid: graph.oid(watermark_pos),
                generation: Some(graph.generation(watermark_pos)),
            }),
        ),
        (
            "generation_mismatch",
            Some(RefWatermark {
                oid: graph.oid(watermark_pos),
                generation: Some(graph.generation(watermark_pos) + 1),
            }),
        ),
        ("missing_watermark", None),
    ];

    let mut group = c.benchmark_group("commit_walk_watermark");
    group.sample_size(10);

    for (label, watermark) in cases {
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &watermark,
            |b, watermark| {
                b.iter_batched(
                    || {
                        vec![StartSetRef {
                            name: ByteRef::new(0, 0),
                            tip: graph.oid(tip_pos),
                            watermark: *watermark,
                        }]
                    },
                    |refs| {
                        let mut iter = CommitPlanIter::new_from_refs(&refs, &graph, limits)
                            .expect("iterator should build");
                        black_box(iter.next().transpose().expect("iteration should succeed"));
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_commit_walk_watermarks);
criterion_main!(benches);
