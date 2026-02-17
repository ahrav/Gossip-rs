use criterion::{Criterion, black_box, criterion_group, criterion_main};

use gossip_contracts::sim::{CoordinationSim, FaultLevel};

fn bench_sunny_day(c: &mut Criterion) {
    c.bench_function("sim_sunny_day_200_100", |b| {
        b.iter(|| {
            let report = CoordinationSim::new(black_box(42), FaultLevel::SunnyDay)
                .with_workers_and_shards(3, 5)
                .run(200, 100);
            black_box(report)
        })
    });
}

fn bench_stormy(c: &mut Criterion) {
    c.bench_function("sim_stormy_500_200", |b| {
        b.iter(|| {
            let report = CoordinationSim::new(black_box(42), FaultLevel::Stormy)
                .with_workers_and_shards(3, 5)
                .run(500, 200);
            black_box(report)
        })
    });
}

fn bench_radioactive(c: &mut Criterion) {
    c.bench_function("sim_radioactive_1000_500", |b| {
        b.iter(|| {
            let report = CoordinationSim::new(black_box(42), FaultLevel::Radioactive)
                .with_workers_and_shards(3, 5)
                .run(1000, 500);
            black_box(report)
        })
    });
}

fn bench_invariant_check(c: &mut Criterion) {
    // Measures per-step cost (op execution + full invariant sweep) on a
    // simulation with 20 shards. The invariant checker runs S1-S7 after
    // every step, so this captures its hot-path cost under realistic state.
    c.bench_function("sim_step_20_shards", |b| {
        b.iter(|| {
            let report = CoordinationSim::new(black_box(42), FaultLevel::SunnyDay)
                .with_workers_and_shards(3, 20)
                .run(50, 0);
            black_box(report)
        })
    });
}

criterion_group!(
    sim_benches,
    bench_sunny_day,
    bench_stormy,
    bench_radioactive,
    bench_invariant_check,
);
criterion_main!(sim_benches);
