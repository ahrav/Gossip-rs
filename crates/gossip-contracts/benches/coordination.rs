//! Criterion benchmarks for `InMemoryCoordinator` hot-path operations.
//!
//! Validates that the two-level shard map, aHash hasher, O(1) shard counting,
//! and `list_shards_into` pre-filter deliver the expected performance characteristics.
//! Acquire/checkpoint benchmarks intentionally use borrowed APIs plus reusable
//! scratch so measurements reflect steady-state (allocation-free) hot paths.
//!
//! # What is measured and why
//!
//! | Benchmark | Operation | Why it matters |
//! |---|---|---|
//! | `acquire` | `acquire_and_restore_into` | Lease acquisition is the entry point for every worker session. Must scale O(1) with shard count via the two-level hash map. |
//! | `checkpoint` | `checkpoint` | The most frequent hot-path call in production (called once per batch of scanned rows). Exercises op-log insert + cursor update. |
//! | `register_shards` | `register_shards` | Bulk shard registration at run creation. Measures per-shard insertion cost into the two-level map and byte slab. |
//! | `list_shards` | `list_shards_into` with filters | Validates that `ShardFilter` pre-filtering avoids full shard scans. Three filter profiles: `all` (baseline), `available` (common), `parked` (zero-match best case). |
//!
//! # Shard count parameters
//!
//! Benchmarks sweep `[1_000, 5_000, 10_000]` shards to detect non-constant
//! scaling. If acquire or checkpoint show linear growth with shard count,
//! the two-level map indexing has regressed. `register_shards` is expected
//! to scale linearly (O(n) insertions), so its sweep uses `[100, 1_000, 10_000]`
//! to measure the per-shard constant factor.
//!
//! # Running
//!
//! ```text
//! cargo bench -p gossip-contracts --bench coordination
//! ```

use criterion::{BatchSize, BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use gossip_contracts::coordination::cursor::CursorUpdate;
use gossip_contracts::coordination::error::AcquireScratch;
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

/// Leak bytes to produce `&'static [u8]` for benchmark shard specs.
///
/// Criterion re-runs the benchmark closure many times. Using `'static`
/// specs avoids re-allocating spec byte vectors on each iteration and
/// keeps the allocation cost out of the measured path.
fn leak_bytes(bytes: Vec<u8>) -> &'static [u8] {
    Box::leak(bytes.into_boxed_slice())
}

/// Build a coordinator with `n` shards registered under a single run.
///
/// Each shard covers a unique 4-byte big-endian range `[i, i+1)`,
/// supporting up to `u32::MAX` shards without key overlap. The slab
/// is sized with headroom (`n + 1000`) to avoid exhaustion during
/// benchmark iterations that allocate additional cursor/spec entries.
fn coordinator_with_shards(n: usize) -> (InMemoryCoordinator, RunId, Vec<ShardId>) {
    let mut coord = InMemoryCoordinator::with_limits(1000, n + 1000, n + 1000);
    let run = RunId::from_raw(1);
    let config = RunConfig::try_new(CursorSemantics::Completed, 1000, None).unwrap();

    coord
        .create_run(LogicalTime::from_raw(1), tenant(), run, config)
        .unwrap();

    // Use 4-byte big-endian ranges to support >256 shards without overlap.
    // Shard i covers [i_be4, (i+1)_be4) where i_be4 is i as 4-byte big-endian.
    let shards: Vec<InitialShardInput<'static>> = (0..n)
        .map(|i| {
            let shard = ShardId::from_raw(i as u64 + 1);
            let lo = leak_bytes((i as u32).to_be_bytes().to_vec());
            let hi = leak_bytes(((i as u32) + 1).to_be_bytes().to_vec());
            let spec = ShardSpecRef::new(lo, hi, &[]);
            InitialShardInput::new(shard, spec, CursorUpdate::initial())
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
                // Reused across iterations to benchmark borrow-path behavior,
                // not per-iteration scratch allocation.
                let mut scratch = AcquireScratch::default();

                b.iter(|| {
                    // Advance time past the previous lease deadline.
                    time = LogicalTime::from_raw(time.as_raw() + 2000);
                    let result = coord
                        .acquire_and_restore_into(time, tenant(), key, worker(), &mut scratch)
                        .unwrap();
                    let _ = black_box(&result);
                });
            },
        );
    }
    group.finish();
}

/// Benchmark checkpoint at different shard counts.
///
/// Checkpoint is the most frequent hot-path operation in production:
/// workers call it once per batch of scanned rows to persist cursor
/// progress. The benchmark acquires a shard once (setup), then
/// repeatedly calls `checkpoint` with incrementing op-IDs and a
/// fixed cursor value. This isolates the cursor-update + op-log
/// insertion cost from the acquire overhead.
///
/// Time is fixed (no lease expiry) so every iteration succeeds.
/// Op-IDs increment monotonically so the op-log never triggers a
/// conflict rejection.
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
                // Reused once for initial acquire; checkpoint benchmark itself
                // measures cursor update/op-log costs.
                let mut scratch = AcquireScratch::default();

                let result = coord
                    .acquire_and_restore_into(time, tenant(), key, worker(), &mut scratch)
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

/// Benchmark bulk shard registration at varying scale.
///
/// Measures the cost of `register_shards` which inserts `n` shard records
/// into the two-level map and allocates spec/cursor storage in the byte
/// slab. Coordinator construction and `create_run` happen in the setup
/// closure (not measured); only `register_shards` is timed.
///
/// The shard spec vectors are pre-allocated (leaked to `'static`) outside
/// the benchmark loop so spec construction cost does not pollute the
/// measurement.
fn bench_register_shards(c: &mut Criterion) {
    let mut group = c.benchmark_group("register_shards");

    for &shard_count in &[100, 1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(shard_count),
            &shard_count,
            |b, &n| {
                let shards: Vec<InitialShardInput<'static>> = (0..n)
                    .map(|i| {
                        let shard = ShardId::from_raw(i as u64 + 1);
                        let lo = leak_bytes((i as u32).to_be_bytes().to_vec());
                        let hi = leak_bytes(((i as u32) + 1).to_be_bytes().to_vec());
                        let spec = ShardSpecRef::new(lo, hi, &[]);
                        InitialShardInput::new(shard, spec, CursorUpdate::initial())
                    })
                    .collect();

                let mut run_counter = 0u64;

                b.iter_batched(
                    || {
                        run_counter += 1;
                        let mut coord = InMemoryCoordinator::with_limits(1000, n + 1000, n + 1000);
                        let run = RunId::from_raw(run_counter);
                        let config =
                            RunConfig::try_new(CursorSemantics::Completed, 1000, None).unwrap();
                        coord
                            .create_run(LogicalTime::from_raw(1), tenant(), run, config)
                            .unwrap();
                        (coord, run, run_counter)
                    },
                    |(mut coord, run, counter)| {
                        let ids = coord
                            .register_shards(
                                LogicalTime::from_raw(2),
                                tenant(),
                                run,
                                &shards,
                                OpId::from_raw(counter),
                            )
                            .unwrap();
                        let _ = black_box(ids);
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

/// Benchmark `list_shards_into` with three filter profiles at 10K shards.
///
/// Validates that `ShardFilter` pre-filtering provides meaningful
/// performance differentiation:
///
/// - **`all`**: no filter benefit -- must iterate all 10K shard records.
///   This is the baseline cost of the full-scan path.
/// - **`available`**: Active + unleased filter. In this benchmark all
///   shards are Active and unleased, so all 10K match. Measures the
///   per-record filter evaluation overhead on top of the full scan.
/// - **`parked`**: zero matches. If the pre-filter uses status-indexed
///   counters or early termination, this should be significantly faster
///   than the `all` case. A similar runtime indicates the pre-filter
///   is not effective.
fn bench_list_shards(c: &mut Criterion) {
    let mut group = c.benchmark_group("list_shards");

    let (coord, run, _ids) = coordinator_with_shards(10_000);

    // Filter: all (no pre-filter benefit)
    group.bench_function("all_10k", |b| {
        let mut summaries = Vec::new();
        b.iter(|| {
            coord
                .list_shards_into(
                    LogicalTime::from_raw(50),
                    tenant(),
                    run,
                    ShardFilter::all(),
                    &mut summaries,
                )
                .unwrap();
            black_box(summaries.len());
        });
    });

    // Filter: available (Active + unleased) — all match since none are leased
    group.bench_function("available_10k", |b| {
        let mut summaries = Vec::new();
        b.iter(|| {
            coord
                .list_shards_into(
                    LogicalTime::from_raw(50),
                    tenant(),
                    run,
                    ShardFilter::available(),
                    &mut summaries,
                )
                .unwrap();
            black_box(summaries.len());
        });
    });

    // Filter: parked — matches 0, maximum pre-filter benefit
    group.bench_function("parked_10k", |b| {
        let mut summaries = Vec::new();
        b.iter(|| {
            coord
                .list_shards_into(
                    LogicalTime::from_raw(50),
                    tenant(),
                    run,
                    ShardFilter::parked(),
                    &mut summaries,
                )
                .unwrap();
            black_box(summaries.len());
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
