//! Benchmarks for the persisted seen-bitmap scope representation.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::{Duration, Instant};

use scanner_git::{OidBytes, RoaringSeenBitmap};

const BITMAP_SIZE: u32 = 1_000_000;
const PROBE_BATCH: u32 = 10_000;

fn oid_from_u32(value: u32) -> OidBytes {
    let mut bytes = [0u8; 20];
    bytes[16..20].copy_from_slice(&value.to_be_bytes());
    OidBytes::sha1(bytes)
}

fn build_bitmap(size: u32) -> RoaringSeenBitmap {
    let oids: Vec<OidBytes> = (0..size).map(oid_from_u32).collect();
    let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
    bitmap.insert_batch(&oids).expect("bitmap");
    bitmap
}

fn build_probe_batch(size: u32) -> Vec<OidBytes> {
    (0..size)
        .map(|idx| {
            if idx % 2 == 0 {
                oid_from_u32(idx)
            } else {
                oid_from_u32(BITMAP_SIZE + idx)
            }
        })
        .collect()
}

fn build_update_batch(start: u32, size: u32) -> Vec<OidBytes> {
    (start..start + size).map(oid_from_u32).collect()
}

fn bench_batch_contains(c: &mut Criterion) {
    let bitmap = build_bitmap(BITMAP_SIZE);
    let probes = build_probe_batch(PROBE_BATCH);

    c.bench_function("roaring_seen/batch_contains_10k_against_1m", |b| {
        b.iter(|| black_box(bitmap.batch_contains(black_box(&probes))))
    });
}

fn bench_serialize(c: &mut Criterion) {
    let bitmap = build_bitmap(BITMAP_SIZE);

    c.bench_function("roaring_seen/serialize_1m", |b| {
        b.iter(|| black_box(bitmap.serialize()))
    });
}

fn bench_insert_batch(c: &mut Criterion) {
    let bitmap = build_bitmap(BITMAP_SIZE);
    let update = build_update_batch(BITMAP_SIZE, PROBE_BATCH);

    c.bench_function("roaring_seen/insert_batch_10k_into_1m", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut working = bitmap.clone();
                let start = Instant::now();
                working
                    .insert_batch(black_box(&update))
                    .expect("insert batch");
                total += start.elapsed();
                black_box(working);
            }
            total
        })
    });
}

criterion_group!(
    benches,
    bench_batch_contains,
    bench_serialize,
    bench_insert_batch
);
criterion_main!(benches);
