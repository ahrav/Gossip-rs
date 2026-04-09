//! Benchmarks for persisted seen-bitmap representations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Once;
use std::time::{Duration, Instant};

use scanner_git::{MidxOrdinalBitset, MidxView, ObjectFormat, OidBytes, RoaringSeenBitmap};

const BITMAP_SIZE: u32 = 1_000_000;
const PROBE_BATCH: u32 = 10_000;
const SCALE_POINTS: [u32; 3] = [100_000, 1_000_000, 10_000_000];
const BENCH_FINGERPRINT: [u8; 32] = [0xA5; 32];
const MIDX_MAGIC: [u8; 4] = *b"MIDX";
const MIDX_VERSION: u8 = 1;
const MIDX_HEADER_SIZE: usize = 12;
const CHUNK_ENTRY_SIZE: usize = 12;
const CHUNK_PNAM: [u8; 4] = *b"PNAM";
const CHUNK_OIDF: [u8; 4] = *b"OIDF";
const CHUNK_OIDL: [u8; 4] = *b"OIDL";
const CHUNK_OOFF: [u8; 4] = *b"OOFF";

fn oid_from_u32(value: u32) -> OidBytes {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&value.to_be_bytes());
    OidBytes::sha1(bytes)
}

fn build_bitmap(size: u32) -> RoaringSeenBitmap {
    let oids: Vec<OidBytes> = (0..size).map(oid_from_u32).collect();
    let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
    bitmap.insert_batch(&oids).expect("bitmap");
    bitmap
}

fn build_ordinal_bitset(size: u32) -> MidxOrdinalBitset {
    let mut bitset = MidxOrdinalBitset::new(size, BENCH_FINGERPRINT);
    for ordinal in 0..size {
        bitset.set(ordinal);
    }
    bitset
}

/// Builds a minimal valid MIDX (v1, SHA-1) for `size` sequential OIDs.
///
/// OIDs are produced by [`oid_from_u32`] which places the big-endian `u32`
/// value in the first four bytes of a 20-byte SHA-1. Because sequential
/// integers are lexicographically ordered under big-endian encoding, the
/// resulting OIDL chunk is sorted by construction. Note that this produces
/// a skewed fanout distribution (only buckets 0x00-0x09 are populated at
/// 10M OIDs), which may not exercise all fanout-bucket cursor transitions.
fn build_midx_bytes(size: u32) -> Vec<u8> {
    let pnam = Vec::from(&b"pack-0.pack\0"[..]);
    let mut oidf = vec![0u8; 256 * 4];
    let mut counts = [0u32; 256];
    let mut oidl = Vec::with_capacity(size as usize * 20);
    let mut ooff = Vec::with_capacity(size as usize * 8);

    for value in 0..size {
        let oid = oid_from_u32(value);
        counts[oid.as_slice()[0] as usize] += 1;
        oidl.extend_from_slice(oid.as_slice());
        ooff.extend_from_slice(&0u32.to_be_bytes());
        ooff.extend_from_slice(&value.to_be_bytes());
    }

    let mut running = 0u32;
    for (idx, count) in counts.iter().enumerate() {
        running += count;
        let off = idx * 4;
        oidf[off..off + 4].copy_from_slice(&running.to_be_bytes());
    }

    let chunk_count = 4u8;
    let chunk_table_size = (chunk_count as usize + 1) * CHUNK_ENTRY_SIZE;
    let pnam_off = (MIDX_HEADER_SIZE + chunk_table_size) as u64;
    let oidf_off = pnam_off + pnam.len() as u64;
    let oidl_off = oidf_off + oidf.len() as u64;
    let ooff_off = oidl_off + oidl.len() as u64;
    let end_off = ooff_off + ooff.len() as u64;

    let mut out = Vec::with_capacity(end_off as usize);
    out.extend_from_slice(&MIDX_MAGIC);
    out.push(MIDX_VERSION);
    out.push(1);
    out.push(chunk_count);
    out.push(0);
    out.extend_from_slice(&1u32.to_be_bytes());

    let mut push_chunk = |id: [u8; 4], off: u64| {
        out.extend_from_slice(&id);
        out.extend_from_slice(&off.to_be_bytes());
    };
    push_chunk(CHUNK_PNAM, pnam_off);
    push_chunk(CHUNK_OIDF, oidf_off);
    push_chunk(CHUNK_OIDL, oidl_off);
    push_chunk(CHUNK_OOFF, ooff_off);
    push_chunk([0, 0, 0, 0], end_off);

    out.extend_from_slice(&pnam);
    out.extend_from_slice(&oidf);
    out.extend_from_slice(&oidl);
    out.extend_from_slice(&ooff);
    out
}

fn build_probe_batch(size: u32) -> Vec<OidBytes> {
    (0..size)
        .map(|idx| {
            if idx % 2 == 0 {
                oid_from_u32(idx)
            } else {
                oid_from_u32(size + idx)
            }
        })
        .collect()
}

fn build_update_batch(start: u32, size: u32) -> Vec<OidBytes> {
    (start..start + size).map(oid_from_u32).collect()
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
    let probes = build_probe_batch(PROBE_BATCH);

    c.bench_function("roaring_seen/batch_contains_10k_against_1m", |b| {
        b.iter(|| black_box(bitmap.batch_contains(black_box(&probes))))
    });
}

fn bench_batch_contains_sorted_scale(c: &mut Criterion, size: u32) {
    let bitmap = build_bitmap(size);
    let ordinal = build_ordinal_bitset(size);
    let midx_bytes = build_midx_bytes(size);
    let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
    let mut probes = build_probe_batch(PROBE_BATCH);
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

criterion_group!(
    benches,
    bench_batch_contains,
    bench_batch_contains_sorted_compare,
    bench_serialize,
    bench_deserialize,
    bench_insert_batch,
    bench_merge
);
criterion_main!(benches);
