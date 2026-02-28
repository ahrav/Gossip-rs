//! Criterion benchmarks for the scan loop hot path.
//!
//! Measures end-to-end pages/sec through `run_scan_loop` with an in-memory
//! connector, isolating the per-page overhead of:
//! - `validate_page` (CPU: byte comparisons over page items)
//! - cursor ownership transfer (previously a clone, now `into_next_cursor`)
//! - `session.checkpoint` (coordination: lease check + cursor update + op-log)
//!
//! Connector I/O dominates wall-clock time in production, but these benchmarks
//! use an in-memory connector so the coordination and validation costs are
//! visible and regression-gated.
//!
//! # Benchmark matrix
//!
//! | Benchmark | What it measures |
//! |---|---|
//! | `scan_loop/pages/{T}_items_{P}_per_page` | End-to-end throughput with T total items, P per page |
//! | `validate_page/{N}` | Isolated `validate_page` cost at N items |
//!
//! # Running
//!
//! ```text
//! cargo bench -p gossip-scan-pipeline --bench scan_loop
//! ```

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use gossip_connectors::{InMemoryDeterministicConnector, MemItem};
use gossip_contracts::connector::{
    Budgets, Cursor, ItemKey, ItemRef, ScanItem, VersionId, validate_page,
};
use gossip_contracts::coordination::{CursorSemantics, CursorUpdate, InitialShardInput, ShardSpec};
use gossip_contracts::identity::{
    ConnectorTag, LogicalTime, ObjectVersionId, OpId, RunId, ShardId, ShardKey, StableItemId,
    TenantId, WorkerId,
};
use gossip_coordination::{InMemoryCoordinator, RunConfig, RunManagement, WorkerSession};
use gossip_scan_pipeline::{DEFAULT_MAX_TRANSIENT_RETRIES, run_scan_loop};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TAG: ConnectorTag = ConnectorTag::from_ascii(b"benchslp");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tenant() -> TenantId {
    TenantId::from_bytes([0x42; 32])
}

fn run_id() -> RunId {
    RunId::from_raw(1)
}

fn shard_id() -> ShardId {
    ShardId::from_raw(1)
}

fn shard_key() -> ShardKey {
    ShardKey::new(run_id(), shard_id())
}

fn worker() -> WorkerId {
    WorkerId::from_raw(1)
}

fn now(tick: u64) -> LogicalTime {
    LogicalTime::from_raw(tick)
}

fn budgets(max_items: usize) -> Budgets {
    Budgets::try_new(max_items, u64::MAX, None).expect("budgets")
}

/// Build a vector of N `MemItem`s with 4-byte big-endian keys.
///
/// Keys are sequential `0..n` in big-endian, giving a dense lexicographic
/// range that the in-memory connector can page through efficiently.
fn make_items(n: usize) -> Vec<MemItem> {
    (0..n)
        .map(|i| {
            let key_bytes = (i as u32).to_be_bytes();
            let key = ItemKey::try_from_slice(&key_bytes).expect("key");
            MemItem::new(key, vec![0xAA; 64])
        })
        .collect()
}

/// Build a coordinator with one shard covering keys `[0x00000000, 0xFFFFFFFF)`.
fn seeded_coordinator(lease_duration: u64) -> InMemoryCoordinator {
    let mut coord = InMemoryCoordinator::new(lease_duration);
    let config =
        RunConfig::try_new(CursorSemantics::Completed, lease_duration, Some(5)).expect("config");
    coord
        .create_run(now(1), tenant(), run_id(), config)
        .expect("create run");

    let spec = ShardSpec::with_range(0u32.to_be_bytes(), u32::MAX.to_be_bytes());
    let shards = [InitialShardInput::new(
        shard_id(),
        spec.as_ref(),
        CursorUpdate::initial(),
    )];
    let _ = coord
        .register_shards(now(2), tenant(), run_id(), &shards, OpId::from_raw(1))
        .expect("register shards");
    coord
}

/// Acquire a fresh session against the coordinator.
fn acquire_session(
    coord: &mut InMemoryCoordinator,
    at: u64,
) -> WorkerSession<'_, InMemoryCoordinator> {
    WorkerSession::new(coord, now(at), tenant(), shard_key(), worker()).expect("acquire session")
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// End-to-end scan loop throughput with varying page sizes.
///
/// Connector holds `total_items` items. The scan loop fetches pages of
/// `page_size` items each, exercises `validate_page` + `checkpoint` per page,
/// then `complete` on the terminal empty page.
///
/// The lease duration is set high enough that no expiry occurs.
fn bench_scan_loop(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_loop");

    // (total_items, page_size) combinations.
    let params: &[(usize, usize)] = &[
        (100, 1),
        (100, 10),
        (100, 100),
        (1_000, 10),
        (1_000, 100),
        (1_000, 1_000),
        (10_000, 100),
    ];

    for &(total, page_size) in params {
        let label = format!("{total}_items_{page_size}_per_page");
        group.bench_with_input(
            BenchmarkId::new("pages", &label),
            &(total, page_size),
            |b, &(total, page_size)| {
                let items = make_items(total);

                b.iter_batched(
                    || {
                        // Fresh coordinator + connector per iteration so each run
                        // starts from cursor=initial and the shard is Active.
                        let coord = seeded_coordinator(1_000_000);
                        let connector = InMemoryDeterministicConnector::new(TAG, items.clone());
                        (coord, connector)
                    },
                    |(mut coord, mut connector)| {
                        let session = acquire_session(&mut coord, 100);
                        let mut op_raw = 1000u64;
                        let mut tick = 101u64;
                        let outcome = run_scan_loop(
                            session,
                            &mut connector,
                            budgets(page_size),
                            DEFAULT_MAX_TRANSIENT_RETRIES,
                            || {
                                let raw = op_raw;
                                op_raw += 1;
                                OpId::from_raw(raw)
                            },
                            || {
                                let out = now(tick);
                                tick += 1;
                                out
                            },
                        );
                        let _ = black_box(outcome);
                    },
                    if total >= 1_000 {
                        criterion::BatchSize::LargeInput
                    } else {
                        criterion::BatchSize::SmallInput
                    },
                );
            },
        );
    }
    group.finish();
}

/// Isolated `validate_page` cost at varying item counts.
///
/// Measures only the CPU work of per-item range and ordering checks, with
/// zero coordination overhead. This establishes the validation baseline
/// so regressions can be attributed to validation vs coordination.
fn bench_validate_page(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_page");

    for &item_count in &[10, 100, 1_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(item_count),
            &item_count,
            |b, &n| {
                let spec = ShardSpec::with_range(0u32.to_be_bytes(), u32::MAX.to_be_bytes());
                let input_cursor = Cursor::initial();

                // Build a valid page of n items with sequential keys.
                let items: Vec<ScanItem> = (0..n)
                    .map(|i| {
                        let key_bytes = (i as u32).to_be_bytes();
                        let key = ItemKey::try_from_slice(&key_bytes).expect("key");
                        let item_ref = ItemRef::try_from_slice(&key_bytes).expect("ref");
                        let stable = StableItemId::from_bytes([i as u8; 32]);
                        let version =
                            VersionId::Strong(ObjectVersionId::from_version_bytes(&key_bytes));
                        ScanItem::new(key, item_ref, stable, version)
                    })
                    .collect();

                let last_key_bytes = ((n - 1) as u32).to_be_bytes();
                let last_key = ItemKey::try_from_slice(&last_key_bytes).expect("last key");
                let next_cursor = Cursor::with_last_key(last_key);

                b.iter(|| {
                    let result =
                        validate_page(&spec, &input_cursor, black_box(&items), &next_cursor);
                    let _ = black_box(result);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(scan_loop_benches, bench_scan_loop, bench_validate_page);
criterion_main!(scan_loop_benches);
