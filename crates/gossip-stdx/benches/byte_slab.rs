use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use gossip_stdx::{ByteSlab, ByteSlot};

const OPS_PER_ITER: u64 = 10_000;

/// Pure bump allocation (no free list involvement).
fn bench_allocate_bump(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_slab");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("allocate_bump_64b", |b| {
        let data = [0xABu8; 64];
        b.iter(|| {
            let mut slab = ByteSlab::with_capacity(1024 * 1024);
            for _ in 0..OPS_PER_ITER {
                let slot = slab.allocate(black_box(&data)).unwrap();
                black_box(slot);
            }
            slab.clear();
        })
    });

    group.bench_function("allocate_bump_256b", |b| {
        let data = [0xABu8; 256];
        b.iter(|| {
            let mut slab = ByteSlab::with_capacity(4 * 1024 * 1024);
            for _ in 0..OPS_PER_ITER {
                let slot = slab.allocate(black_box(&data)).unwrap();
                black_box(slot);
            }
            slab.clear();
        })
    });

    group.finish();
}

/// Allocation from free list (pre-populated with freed blocks).
fn bench_allocate_freelist_reuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_slab");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("allocate_freelist_reuse_64b", |b| {
        let data = [0xABu8; 64];
        // Pre-build a slab with one free block to reuse repeatedly.
        b.iter(|| {
            let mut slab = ByteSlab::with_capacity(64 * 1024);
            // Pin: allocate a small block at the end to prevent bump reclamation.
            let pin = slab.allocate(&[0u8; 1]).unwrap();

            for _ in 0..OPS_PER_ITER {
                let slot = slab.allocate(black_box(&data)).unwrap();
                slab.deallocate(slot);
            }

            slab.deallocate(pin);
            slab.clear();
        })
    });

    group.finish();
}

/// Dealloc of trailing block (bump pointer reclamation).
fn bench_deallocate_bump_reclaim(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_slab");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("deallocate_bump_reclaim_64b", |b| {
        let data = [0xABu8; 64];
        b.iter(|| {
            let mut slab = ByteSlab::with_capacity(64 * 1024);
            for _ in 0..OPS_PER_ITER {
                let slot = slab.allocate(black_box(&data)).unwrap();
                slab.deallocate(slot);
            }
        })
    });

    group.finish();
}

/// Dealloc into free list (no coalescing — pinned neighbors).
fn bench_deallocate_freelist_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_slab");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("deallocate_freelist_insert", |b| {
        let data = [0xABu8; 64];
        b.iter(|| {
            let mut slab = ByteSlab::with_capacity(256 * 1024);
            let mut pins = Vec::with_capacity(OPS_PER_ITER as usize);
            let mut targets = Vec::with_capacity(OPS_PER_ITER as usize);

            // Interleave: [target][pin][target][pin]...
            // Pins prevent coalescing, forcing free-list insert.
            for _ in 0..OPS_PER_ITER {
                let target = slab.allocate(black_box(&data)).unwrap();
                let pin = slab.allocate(&[0u8; 1]).unwrap();
                targets.push(target);
                pins.push(pin);
            }

            // Deallocate targets — each goes into the free list.
            for slot in targets {
                slab.deallocate(slot);
            }

            // Cleanup.
            for slot in pins {
                slab.deallocate(slot);
            }
            slab.clear();
        })
    });

    group.finish();
}

/// Dealloc with coalescing (adjacent free blocks merge).
fn bench_deallocate_coalesce(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_slab");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("deallocate_coalesce_pairs", |b| {
        let data = [0xABu8; 64];
        b.iter(|| {
            let mut slab = ByteSlab::with_capacity(256 * 1024);
            let mut slots = Vec::with_capacity((OPS_PER_ITER * 2) as usize);

            // Allocate pairs of adjacent blocks.
            for _ in 0..OPS_PER_ITER {
                let a = slab.allocate(black_box(&data)).unwrap();
                let b_slot = slab.allocate(black_box(&data)).unwrap();
                slots.push((a, b_slot));
            }

            // Free second of each pair first, then first — triggers coalescing.
            for (a, b_slot) in slots {
                slab.deallocate(b_slot);
                slab.deallocate(a);
            }
        })
    });

    group.finish();
}

/// Read-back via `get()`.
fn bench_get_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_slab");

    let data_64 = [0xABu8; 64];
    let data_256 = [0xABu8; 256];

    // Pre-allocate slab with live slots.
    let mut slab = ByteSlab::with_capacity(64 * 1024);
    let slot_64 = slab.allocate(&data_64).unwrap();
    let slot_256 = slab.allocate(&data_256).unwrap();

    group.bench_function("get_64b", |b| {
        b.iter(|| black_box(slab.get(black_box(slot_64))))
    });

    group.bench_function("get_256b", |b| {
        b.iter(|| black_box(slab.get(black_box(slot_256))))
    });

    group.bench_function("get_empty", |b| {
        b.iter(|| black_box(slab.get(black_box(ByteSlot::EMPTY))))
    });

    slab.deallocate(slot_64);
    slab.deallocate(slot_256);

    group.finish();
}

/// Alloc+dealloc+realloc cycle (mimics cursor checkpoint pattern).
fn bench_cursor_update_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_slab");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("cursor_update_cycle", |b| {
        b.iter(|| {
            let mut slab = ByteSlab::with_capacity(64 * 1024);
            let key_data = b"cursor_key_initial";
            let token_data = b"token_data_bytes";

            let mut key = slab.allocate(black_box(key_data.as_slice())).unwrap();
            let mut token = slab.allocate(black_box(token_data.as_slice())).unwrap();

            for i in 0..OPS_PER_ITER {
                // Read current values.
                black_box(slab.get(key));
                black_box(slab.get(token));

                // Update: dealloc old, alloc new (slightly different sizes).
                slab.deallocate(key);
                slab.deallocate(token);

                let suffix = (i % 100) as u8;
                let new_key: Vec<u8> = [b"cursor_key_updated_".as_slice(), &[suffix]].concat();
                let new_token: Vec<u8> =
                    [b"token_data_updated_".as_slice(), &[suffix, suffix]].concat();

                key = slab.allocate(black_box(&new_key)).unwrap();
                token = slab.allocate(black_box(&new_token)).unwrap();
            }

            slab.deallocate(key);
            slab.deallocate(token);
        })
    });

    group.finish();
}

/// Alloc 3-5 fields (mimics shard init).
fn bench_shard_creation_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_slab");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("shard_create_3_fields", |b| {
        b.iter(|| {
            let mut slab = ByteSlab::with_capacity(256 * 1024);
            for _ in 0..OPS_PER_ITER {
                let s = slab
                    .allocate(black_box(b"shard_start_key_001".as_slice()))
                    .unwrap();
                let e = slab
                    .allocate(black_box(b"shard_end_key_001".as_slice()))
                    .unwrap();
                let m = slab.allocate(black_box(b"metadata".as_slice())).unwrap();

                black_box(slab.get(s));
                black_box(slab.get(e));
                black_box(slab.get(m));

                slab.deallocate(s);
                slab.deallocate(e);
                slab.deallocate(m);
            }
        })
    });

    group.bench_function("shard_create_5_fields", |b| {
        b.iter(|| {
            let mut slab = ByteSlab::with_capacity(512 * 1024);
            for _ in 0..OPS_PER_ITER {
                let s = slab
                    .allocate(black_box(b"shard_start_key_001".as_slice()))
                    .unwrap();
                let e = slab
                    .allocate(black_box(b"shard_end_key_001".as_slice()))
                    .unwrap();
                let m = slab.allocate(black_box(b"metadata".as_slice())).unwrap();
                let ck = slab
                    .allocate(black_box(b"cursor_last_key_value".as_slice()))
                    .unwrap();
                let ct = slab
                    .allocate(black_box(b"cursor_token_data_bytes".as_slice()))
                    .unwrap();

                black_box(slab.get(s));
                black_box(slab.get(e));
                black_box(slab.get(m));
                black_box(slab.get(ck));
                black_box(slab.get(ct));

                slab.deallocate(s);
                slab.deallocate(e);
                slab.deallocate(m);
                slab.deallocate(ck);
                slab.deallocate(ct);
            }
        })
    });

    group.finish();
}

/// Random alloc/dealloc mix with varying sizes.
fn bench_mixed_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_slab");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("mixed_workload", |b| {
        // Deterministic xorshift32 for reproducibility.
        struct Rng(u32);
        impl Rng {
            fn next(&mut self) -> u32 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 17;
                self.0 ^= self.0 << 5;
                self.0
            }
        }

        b.iter(|| {
            let mut rng = Rng(0xCAFE_BABE);
            let mut slab = ByteSlab::with_capacity(512 * 1024);
            let mut live: Vec<ByteSlot> = Vec::with_capacity(128);

            for _ in 0..OPS_PER_ITER {
                let should_alloc = live.is_empty() || rng.next() % 100 < 60;

                if should_alloc {
                    let size = 1 + (rng.next() % 512) as usize;
                    let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
                    if let Ok(slot) = slab.allocate(black_box(&data)) {
                        live.push(slot);
                    }
                } else {
                    let idx = rng.next() as usize % live.len();
                    let slot = live.swap_remove(idx);
                    slab.deallocate(slot);
                }
            }

            // Cleanup.
            for slot in live {
                slab.deallocate(slot);
            }
        })
    });

    group.finish();
}

/// `Box<[u8]>` baseline for comparison — same operations with heap allocs.
fn bench_box_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("byte_slab");
    group.throughput(Throughput::Elements(OPS_PER_ITER));

    group.bench_function("box_baseline_alloc_dealloc_64b", |b| {
        let data = [0xABu8; 64];
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let boxed: Box<[u8]> = black_box(&data[..]).into();
                black_box(boxed);
            }
        })
    });

    group.bench_function("box_baseline_shard_create_3_fields", |b| {
        b.iter(|| {
            for _ in 0..OPS_PER_ITER {
                let s: Box<[u8]> = black_box(b"shard_start_key_001".as_slice()).into();
                let e: Box<[u8]> = black_box(b"shard_end_key_001".as_slice()).into();
                let m: Box<[u8]> = black_box(b"metadata".as_slice()).into();

                black_box(&*s);
                black_box(&*e);
                black_box(&*m);
            }
        })
    });

    group.bench_function("box_baseline_cursor_update_cycle", |b| {
        b.iter(|| {
            let mut key: Box<[u8]> = black_box(b"cursor_key_initial".as_slice()).into();
            let mut token: Box<[u8]> = black_box(b"token_data_bytes".as_slice()).into();

            for i in 0..OPS_PER_ITER {
                black_box(&*key);
                black_box(&*token);

                let suffix = (i % 100) as u8;
                let new_key: Vec<u8> = [b"cursor_key_updated_".as_slice(), &[suffix]].concat();
                let new_token: Vec<u8> =
                    [b"token_data_updated_".as_slice(), &[suffix, suffix]].concat();

                key = black_box(new_key.into_boxed_slice());
                token = black_box(new_token.into_boxed_slice());
            }

            black_box(key);
            black_box(token);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_allocate_bump,
    bench_allocate_freelist_reuse,
    bench_deallocate_bump_reclaim,
    bench_deallocate_freelist_insert,
    bench_deallocate_coalesce,
    bench_get_read,
    bench_cursor_update_cycle,
    bench_shard_creation_pattern,
    bench_mixed_workload,
    bench_box_baseline,
);

criterion_main!(benches);
