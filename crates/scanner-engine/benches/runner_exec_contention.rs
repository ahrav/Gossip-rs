//! Benchmark: Concurrent output contention patterns.
//!
//! Measures the per-slot atomic pattern for storing per-task results:
//!
//! - **`per_slot_atomic`**: Each thread locks only its own
//!   `Mutex<Option<[u8;64]>>` slot and checks an `AtomicBool` for abort.
//!
//! Each "task" hashes a 64-byte buffer to prevent dead-code elimination,
//! then stores the result. Uses `std::thread::scope` with explicit thread counts.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Deterministic lightweight hash to simulate per-task work.
///
/// Not cryptographic — just enough ALU work to prevent the compiler from
/// eliding the "task body" while keeping the benchmark focused on
/// synchronization overhead.
#[inline(never)]
fn hash_work(seed: u64) -> [u8; 64] {
    let mut state = seed ^ 0x517cc1b727220a95;
    let mut out = [0u8; 64];
    for chunk in out.chunks_exact_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes());
    }
    out
}

/// Per-slot mutex + atomic abort flag.
///
/// Each thread only locks its own slot. Abort is checked via a cheap
/// `AtomicBool::load(Relaxed)` — no mutex acquisition.
fn per_slot_atomic(thread_count: usize, tasks: usize) {
    let slots: Vec<Mutex<Option<[u8; 64]>>> = (0..tasks).map(|_| Mutex::new(None)).collect();
    let abort = AtomicBool::new(false);

    std::thread::scope(|s| {
        for t in 0..thread_count {
            let slots = &slots;
            let abort = &abort;
            s.spawn(move || {
                let chunk = tasks / thread_count;
                let start = t * chunk;
                let end = if t == thread_count - 1 {
                    tasks
                } else {
                    start + chunk
                };
                for (i, slot) in slots.iter().enumerate().take(end).skip(start) {
                    if abort.load(Ordering::Relaxed) {
                        return;
                    }
                    let val = hash_work(i as u64);
                    *slot.lock().unwrap() = Some(val);
                }
            });
        }
    });

    black_box(&slots);
}

fn bench_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("runner_exec_contention");
    // Fixed task count so we measure contention, not work volume.
    let tasks = 4096;

    for &threads in &[1, 4, 8, 16, 24] {
        group.bench_with_input(
            BenchmarkId::new("per_slot_atomic", threads),
            &threads,
            |b, &tc| {
                b.iter(|| per_slot_atomic(tc, tasks));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_contention);
criterion_main!(benches);
