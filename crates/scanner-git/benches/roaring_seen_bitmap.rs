//! Benchmarks for persisted seen-bitmap representations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Once;
use std::time::{Duration, Instant};

use scanner_git::{
    BytesView, HybridSeenStore, MidxBuilder, MidxOrdinalBitset, MidxView, ObjectFormat, OidBytes,
    RepoArtifactFingerprint, RoaringSeenBitmap, RoaringSeenStore, SeenBlobStore,
};

const BITMAP_SIZE: u32 = 1_000_000;
const PROBE_BATCH: u32 = 10_000;
const SCALE_POINTS: [u32; 3] = [100_000, 1_000_000, 10_000_000];
const BENCH_FINGERPRINT: [u8; 32] = [0xA5; 32];

/// Generates a deterministic OID that spreads across all 256 fanout buckets.
///
/// Hashing the counter distributes the first byte uniformly, so benchmark
/// MIDX fanout tables mirror real-world distributions instead of cramming
/// every entry into bucket 0.
fn oid_from_u32(value: u32) -> OidBytes {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    let h = hasher.finish();
    let mut bytes = [0u8; 20];
    bytes[..8].copy_from_slice(&h.to_le_bytes());
    // Embed the original counter so distinct inputs never collide on 20 bytes.
    bytes[8..12].copy_from_slice(&value.to_be_bytes());
    OidBytes::sha1(bytes)
}

fn build_bitmap(size: u32) -> RoaringSeenBitmap {
    let oids: Vec<OidBytes> = (0..size).map(oid_from_u32).collect();
    let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
    bitmap.insert_batch(&oids).expect("bitmap");
    bitmap
}

fn bench_fingerprint(tag: u8) -> RepoArtifactFingerprint {
    RepoArtifactFingerprint {
        packs_hash: [tag; 32],
        idx_hash: [tag.wrapping_add(1); 32],
    }
}

fn build_ordinal_bitset(size: u32) -> MidxOrdinalBitset {
    let mut bitset = MidxOrdinalBitset::new(size, BENCH_FINGERPRINT);
    for ordinal in 0..size {
        bitset.set(ordinal);
    }
    bitset
}

fn build_midx_bytes(size: u32) -> Vec<u8> {
    let mut builder = MidxBuilder::new();
    builder.add_pack(b"pack-0.pack");
    for value in 0..size {
        let oid = oid_from_u32(value);
        let raw: [u8; 20] = oid.as_slice().try_into().expect("SHA-1 is 20 bytes");
        builder.add_object(raw, 0, value as u64);
    }
    builder.build()
}

fn build_probe_batch(probe_count: u32, dataset_size: u32) -> Vec<OidBytes> {
    (0..probe_count)
        .map(|idx| {
            if idx % 2 == 0 {
                // Hit: OID exists in the dataset.
                oid_from_u32(idx)
            } else {
                // Miss: OID beyond the dataset range.
                oid_from_u32(dataset_size + idx)
            }
        })
        .collect()
}

fn build_update_batch(start: u32, size: u32) -> Vec<OidBytes> {
    (start..start + size).map(oid_from_u32).collect()
}

fn build_hybrid_store(size: u32, loose_seen: u32) -> HybridSeenStore {
    let mut bitmap = build_bitmap(size);
    let loose = build_update_batch(size + PROBE_BATCH, loose_seen);
    bitmap.insert_batch(&loose).expect("loose bitmap");
    HybridSeenStore::with_midx(
        RoaringSeenStore::new(bitmap),
        BytesView::from_vec(build_midx_bytes(size)),
        ObjectFormat::Sha1,
        bench_fingerprint(0x31),
    )
    .expect("hybrid store")
}

fn build_hybrid_probe_batch(probe_count: u32, dataset_size: u32) -> Vec<OidBytes> {
    let loose_base = dataset_size + PROBE_BATCH;
    (0..probe_count)
        .map(|idx| match idx % 4 {
            0 | 1 => oid_from_u32(idx % dataset_size),
            2 => oid_from_u32(loose_base + idx),
            _ => oid_from_u32(loose_base + probe_count + idx),
        })
        .collect()
}

fn report_memory_profiles() {
    static REPORT: Once = Once::new();
    REPORT.call_once(|| {
        for size in SCALE_POINTS {
            let roaring = build_bitmap(size);
            let ordinal = build_ordinal_bitset(size);
            println!(
                "memory_profile size={size} roaring_heap_bytes={} ordinal_heap_bytes={} ratio={:.2}",
                roaring.heap_bytes(),
                ordinal.heap_bytes(),
                roaring.heap_bytes() as f64 / ordinal.heap_bytes() as f64
            );
        }
    });
}

fn bench_batch_contains(c: &mut Criterion) {
    let bitmap = build_bitmap(BITMAP_SIZE);
    let probes = build_probe_batch(PROBE_BATCH, BITMAP_SIZE);

    c.bench_function("roaring_seen/batch_contains_10k_against_1m", |b| {
        b.iter(|| black_box(bitmap.batch_contains(black_box(&probes))))
    });
}

fn bench_batch_contains_sorted_scale(c: &mut Criterion, size: u32) {
    let bitmap = build_bitmap(size);
    let ordinal = build_ordinal_bitset(size);
    let midx_bytes = build_midx_bytes(size);
    let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
    let mut probes = build_probe_batch(PROBE_BATCH, size);
    probes.sort_unstable();

    // Sorted probes with duplicates retained (exercises the dedup fast path).
    let probes_with_dups = probes.clone();
    probes.dedup();

    c.bench_function(
        &format!("roaring_seen/batch_contains_sorted_10k_against_{size}"),
        |b| b.iter(|| black_box(bitmap.batch_contains_sorted(black_box(&probes)))),
    );
    c.bench_function(
        &format!("ordinal_seen/batch_contains_sorted_10k_against_{size}"),
        |b| {
            b.iter(|| {
                black_box(
                    ordinal
                        .batch_contains_sorted(black_box(&midx), black_box(&probes))
                        .expect("batch lookup"),
                )
            })
        },
    );
    c.bench_function(
        &format!("ordinal_seen/batch_contains_sorted_10k_with_dups_against_{size}"),
        |b| {
            b.iter(|| {
                black_box(
                    ordinal
                        .batch_contains_sorted(black_box(&midx), black_box(&probes_with_dups))
                        .expect("batch lookup"),
                )
            })
        },
    );
}

fn bench_batch_contains_sorted_compare(c: &mut Criterion) {
    report_memory_profiles();
    for size in SCALE_POINTS {
        bench_batch_contains_sorted_scale(c, size);
    }
}

fn bench_hybrid_batch_check_seen_compare(c: &mut Criterion) {
    for size in SCALE_POINTS {
        let hybrid = build_hybrid_store(size, PROBE_BATCH);
        hybrid.rebuild_from_fallback().expect("warm ordinal cache");
        let bitmap = hybrid.fallback().bitmap().clone();
        let mut probes = build_hybrid_probe_batch(PROBE_BATCH, size);
        probes.sort_unstable();

        assert_eq!(
            hybrid.batch_check_seen(&probes).expect("hybrid query"),
            bitmap.batch_contains_sorted(&probes),
        );

        c.bench_function(
            &format!("roaring_seen/batch_contains_sorted_mixed_10k_against_{size}"),
            |b| b.iter(|| black_box(bitmap.batch_contains_sorted(black_box(&probes)))),
        );
        c.bench_function(
            &format!("hybrid_seen/batch_check_seen_mixed_10k_against_{size}"),
            |b| b.iter(|| black_box(hybrid.batch_check_seen(black_box(&probes)).expect("hybrid"))),
        );
    }
}

fn bench_serialize(c: &mut Criterion) {
    let bitmap = build_bitmap(BITMAP_SIZE);

    c.bench_function("roaring_seen/serialize_1m", |b| {
        b.iter(|| black_box(bitmap.serialize().expect("serialize")))
    });
}

fn bench_deserialize(c: &mut Criterion) {
    let bytes = build_bitmap(BITMAP_SIZE).serialize().expect("serialize");

    c.bench_function("roaring_seen/deserialize_1m", |b| {
        b.iter(|| {
            black_box(RoaringSeenBitmap::deserialize(black_box(&bytes)).expect("deserialize"))
        })
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

fn bench_merge(c: &mut Criterion) {
    let base = build_bitmap(BITMAP_SIZE);
    let update_oids: Vec<OidBytes> = (BITMAP_SIZE..BITMAP_SIZE + PROBE_BATCH)
        .map(oid_from_u32)
        .collect();
    let mut update = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
    update.insert_batch(&update_oids).expect("update bitmap");

    c.bench_function("roaring_seen/merge_10k_into_1m", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut working = base.clone();
                let start = Instant::now();
                working.merge(black_box(&update)).expect("merge");
                total += start.elapsed();
                black_box(working);
            }
            total
        })
    });
}

fn bench_hybrid_rebuild(c: &mut Criterion) {
    let base = build_hybrid_store(BITMAP_SIZE, 100_000);

    c.bench_function("hybrid_seen/rebuild_from_fallback_1m", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let working = base.clone();
                let start = Instant::now();
                working.rebuild_from_fallback().expect("rebuild");
                total += start.elapsed();
                black_box(working);
            }
            total
        })
    });
}

/// Cold-start benchmark: measures `batch_check_seen` on a freshly constructed
/// hybrid store whose ordinal cache has NOT been pre-warmed. This captures the
/// cost of the lazy rebuild that happens on the first query.
fn bench_hybrid_cold_start(c: &mut Criterion) {
    let base = build_hybrid_store(BITMAP_SIZE, PROBE_BATCH);
    let mut probes = build_hybrid_probe_batch(PROBE_BATCH, BITMAP_SIZE);
    probes.sort_unstable();

    c.bench_function("hybrid_seen/batch_check_seen_cold_start_1m", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let working = base.clone();
                let start = Instant::now();
                let _result = working.batch_check_seen(black_box(&probes)).expect("cold");
                total += start.elapsed();
                black_box(_result);
            }
            total
        })
    });
}

criterion_group!(
    benches,
    bench_batch_contains,
    bench_batch_contains_sorted_compare,
    bench_hybrid_batch_check_seen_compare,
    bench_serialize,
    bench_deserialize,
    bench_insert_batch,
    bench_merge,
    bench_hybrid_rebuild,
    bench_hybrid_cold_start
);
criterion_main!(benches);
