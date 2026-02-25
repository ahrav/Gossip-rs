//! Criterion benchmarks for InMemoryCoordinator hot-path operations.
//!
//! Validates that the two-level shard map, aHash hasher, O(1) shard counting,
//! and list_shards pre-filter deliver the expected performance characteristics.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use gossip_contracts::coordination::cursor::CursorUpdate;
use gossip_contracts::coordination::in_memory::InMemoryCoordinator;
use gossip_contracts::coordination::run::{
    InitialShardInput, RunConfig, RunManagement, ShardFilter,
};
use gossip_contracts::coordination::shard_spec::{CursorSemantics, ShardSpecRef};
use gossip_contracts::coordination::traits::CoordinationBackend;
use gossip_contracts::identity::{LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tenant() -> TenantId {
    TenantId::from_bytes([1u8; 32])
}

fn worker() -> WorkerId {
    WorkerId::from_raw(1)
}

/// Build a coordinator with `n` shards registered under a single run.
fn coordinator_with_shards(n: usize) -> (InMemoryCoordinator, RunId, Vec<ShardId>) {
    let mut coord = InMemoryCoordinator::with_limits(1000, n + 1000, n + 1000);
    let run = RunId::from_raw(1);
    let config = RunConfig::try_new(CursorSemantics::Completed, 1000, None).unwrap();

    coord
        .create_run(LogicalTime::from_raw(1), tenant(), run, config)
        .unwrap();

    // Use 4-byte big-endian ranges to support >256 shards without overlap.
    // Shard i covers [i_be4, (i+1)_be4) where i_be4 is i as 4-byte big-endian.
    let ranges: Vec<([u8; 4], [u8; 4])> = (0..n)
        .map(|i| ((i as u32).to_be_bytes(), ((i as u32) + 1).to_be_bytes()))
        .collect();
    let shards: Vec<InitialShardInput<'_>> = ranges
        .iter()
        .enumerate()
        .map(|(i, (lo, hi))| {
            InitialShardInput::new(
                ShardId::from_raw(i as u64 + 1),
                ShardSpecRef::new(lo.as_slice(), hi.as_slice(), b""),
                CursorUpdate::initial(),
            )
        })
        .collect();

    let op_id = OpId::from_raw(1);
    let ids = coord
        .register_shards(LogicalTime::from_raw(2), tenant(), run, &shards, op_id)
        .unwrap()
        .into_inner();

    (coord, run, ids)
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// Benchmark acquire_and_restore at different shard counts.
///
/// Each iteration acquires the same shard (with advancing time to expire
/// the previous lease). This measures the point-lookup cost through the
/// two-level map at increasing scale.
fn bench_acquire(c: &mut Criterion) {
    let mut group = c.benchmark_group("acquire");

    for &shard_count in &[1_000, 5_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(shard_count),
            &shard_count,
            |b, &n| {
                let (mut coord, _run, ids) = coordinator_with_shards(n);
                let shard = ids[n / 2]; // middle shard
                let run = RunId::from_raw(1);
                let key = ShardKey::new(run, shard);
                let mut time = LogicalTime::from_raw(100);

                b.iter(|| {
                    // Advance time past the previous lease deadline.
                    time = LogicalTime::from_raw(time.as_raw() + 2000);
                    let result = coord
                        .acquire_and_restore(time, tenant(), key, worker())
                        .unwrap();
                    let _ = black_box(result);
                });
            },
        );
    }
    group.finish();
}

/// Benchmark checkpoint (the most frequent hot-path operation).
fn bench_checkpoint(c: &mut Criterion) {
    let mut group = c.benchmark_group("checkpoint");

    for &shard_count in &[1_000, 5_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(shard_count),
            &shard_count,
            |b, &n| {
                let (mut coord, _run, ids) = coordinator_with_shards(n);
                let shard = ids[n / 2];
                let run = RunId::from_raw(1);
                let key = ShardKey::new(run, shard);
                let time = LogicalTime::from_raw(100);
                let mut op_counter = 1000u64;

                let result = coord
                    .acquire_and_restore(time, tenant(), key, worker())
                    .unwrap();
                let lease = result.lease;

                b.iter(|| {
                    op_counter += 1;
                    let cursor = CursorUpdate::new(&[0x42]);
                    let r = coord.checkpoint(
                        time,
                        tenant(),
                        &lease,
                        &cursor,
                        OpId::from_raw(op_counter),
                    );
                    let _ = black_box(r);
                });
            },
        );
    }
    group.finish();
}

fn bench_register_shards(c: &mut Criterion) {
    let mut group = c.benchmark_group("register_shards");

    for &shard_count in &[100, 1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(shard_count),
            &shard_count,
            |b, &n| {
                let ranges: Vec<([u8; 4], [u8; 4])> = (0..n)
                    .map(|i| ((i as u32).to_be_bytes(), ((i as u32) + 1).to_be_bytes()))
                    .collect();
                let shards: Vec<InitialShardInput<'_>> = ranges
                    .iter()
                    .enumerate()
                    .map(|(i, (lo, hi))| {
                        InitialShardInput::new(
                            ShardId::from_raw(i as u64 + 1),
                            ShardSpecRef::new(lo.as_slice(), hi.as_slice(), b""),
                            CursorUpdate::initial(),
                        )
                    })
                    .collect();

                let mut run_counter = 0u64;

                b.iter(|| {
                    run_counter += 1;
                    let mut coord = InMemoryCoordinator::with_limits(1000, n + 1000, n + 1000);
                    let run = RunId::from_raw(run_counter);
                    let config =
                        RunConfig::try_new(CursorSemantics::Completed, 1000, None).unwrap();

                    coord
                        .create_run(LogicalTime::from_raw(1), tenant(), run, config)
                        .unwrap();
                    let ids = coord
                        .register_shards(
                            LogicalTime::from_raw(2),
                            tenant(),
                            run,
                            &shards,
                            OpId::from_raw(run_counter),
                        )
                        .unwrap();
                    let _ = black_box(ids);
                });
            },
        );
    }
    group.finish();
}

fn bench_list_shards(c: &mut Criterion) {
    let mut group = c.benchmark_group("list_shards");

    let (coord, run, _ids) = coordinator_with_shards(10_000);

    // Filter: all (no pre-filter benefit)
    group.bench_function("all_10k", |b| {
        b.iter(|| {
            let result = coord
                .list_shards(LogicalTime::from_raw(50), tenant(), run, ShardFilter::all())
                .unwrap();
            black_box(result.len());
        });
    });

    // Filter: available (Active + unleased) — all match since none are leased
    group.bench_function("available_10k", |b| {
        b.iter(|| {
            let result = coord
                .list_shards(
                    LogicalTime::from_raw(50),
                    tenant(),
                    run,
                    ShardFilter::available(),
                )
                .unwrap();
            black_box(result.len());
        });
    });

    // Filter: parked — matches 0, maximum pre-filter benefit
    group.bench_function("parked_10k", |b| {
        b.iter(|| {
            let result = coord
                .list_shards(
                    LogicalTime::from_raw(50),
                    tenant(),
                    run,
                    ShardFilter::parked(),
                )
                .unwrap();
            black_box(result.len());
        });
    });

    group.finish();
}

criterion_group!(
    coordination_benches,
    bench_acquire,
    bench_checkpoint,
    bench_register_shards,
    bench_list_shards,
);
criterion_main!(coordination_benches);
