//! Criterion benchmarks for pack_inflate hot paths.
//!
//! Measures `apply_delta_into` (exercises `decode_copy_params`) and
//! `inflate_limited` pre-reserve impact.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scanner_git::pack_inflate;

/// Build a LEB128 varint encoding of `value`.
fn push_varint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        out.push(b);
        if value == 0 {
            break;
        }
    }
}

/// Build a synthetic delta that copies `n_copies` regions from the base.
///
/// Each copy command uses all 7 parameter bytes (4 offset + 3 size),
/// stressing `decode_copy_params` maximally.
fn build_copy_heavy_delta(base_len: usize, n_copies: usize, copy_size: usize) -> Vec<u8> {
    let result_len = n_copies * copy_size;
    assert!(copy_size <= base_len, "copy_size must fit within base");
    assert!(result_len > 0);

    let mut delta = Vec::new();
    push_varint(base_len, &mut delta);
    push_varint(result_len, &mut delta);

    for _ in 0..n_copies {
        // Copy command: high bit set, all 4 offset bits + all 3 size bits
        // cmd = 0x80 | off_mask(0x0f) | size_mask(0x07 << 4) = 0xFF
        // But we need offset=0 and size=copy_size.
        // Encode with minimal bits needed.
        let offset: usize = 0;
        let size = copy_size;

        // Determine which bytes we need for offset (little-endian).
        let off_bytes = [
            (offset & 0xFF) as u8,
            ((offset >> 8) & 0xFF) as u8,
            ((offset >> 16) & 0xFF) as u8,
            ((offset >> 24) & 0xFF) as u8,
        ];
        let size_bytes = [
            (size & 0xFF) as u8,
            ((size >> 8) & 0xFF) as u8,
            ((size >> 16) & 0xFF) as u8,
        ];

        // Use all offset and size bytes for maximum decode_copy_params pressure.
        let cmd: u8 = 0x80 | 0x0F | 0x70; // all 4 off bits + all 3 size bits
        delta.push(cmd);
        for &b in &off_bytes {
            delta.push(b);
        }
        for &b in &size_bytes {
            delta.push(b);
        }
    }

    delta
}

/// Build a mixed delta with both copy and insert commands.
fn build_mixed_delta(base_len: usize) -> Vec<u8> {
    // Alternate: copy 64 bytes from base, insert 32 bytes literal.
    let copy_size = 64;
    let insert_size = 32;
    let n_rounds = 50;
    let result_len = n_rounds * (copy_size + insert_size);

    assert!(copy_size <= base_len);

    let mut delta = Vec::new();
    push_varint(base_len, &mut delta);
    push_varint(result_len, &mut delta);

    for _ in 0..n_rounds {
        // Copy command: offset=0, size=64
        // Use 1 offset byte + 1 size byte for a realistic mix.
        let cmd: u8 = 0x80 | 0x01 | 0x10; // off bit 0 + size bit 0
        delta.push(cmd);
        delta.push(0x00); // offset byte 0 = 0
        delta.push(copy_size as u8); // size byte 0 = 64

        // Insert command: size in cmd byte (1-127), followed by literal data.
        delta.push(insert_size as u8);
        for j in 0..insert_size {
            delta.push((j & 0xFF) as u8);
        }
    }

    delta
}

fn bench_apply_delta_into(c: &mut Criterion) {
    let mut group = c.benchmark_group("apply_delta_into");

    // --- Copy-heavy: stress decode_copy_params with all 7 param bytes ---
    {
        let base_len = 65536;
        let base = vec![0xA5u8; base_len];
        let n_copies = 50;
        let copy_size = 1024;
        let delta = build_copy_heavy_delta(base_len, n_copies, copy_size);
        let result_len = n_copies * copy_size;

        group.throughput(Throughput::Bytes(result_len as u64));
        group.bench_with_input(
            BenchmarkId::new("copy_heavy", format!("{n_copies}x{copy_size}")),
            &(&base, &delta),
            |b, &(base, delta)| {
                b.iter(|| {
                    let mut total = 0usize;
                    pack_inflate::apply_delta_into(
                        black_box(base),
                        black_box(delta),
                        result_len,
                        |chunk| {
                            total += chunk.len();
                            Ok(())
                        },
                    )
                    .unwrap();
                    black_box(total);
                });
            },
        );
    }

    // --- Mixed: realistic alternation of copy + insert ---
    {
        let base_len = 65536;
        let base = vec![0xA5u8; base_len];
        let delta = build_mixed_delta(base_len);
        let (_, result_len) = pack_inflate::delta_sizes(&delta).unwrap();

        group.throughput(Throughput::Bytes(result_len as u64));
        group.bench_with_input(
            BenchmarkId::new("mixed", "50rounds"),
            &(&base, &delta),
            |b, &(base, delta)| {
                b.iter(|| {
                    let mut total = 0usize;
                    pack_inflate::apply_delta_into(
                        black_box(base),
                        black_box(delta),
                        result_len,
                        |chunk| {
                            total += chunk.len();
                            Ok(())
                        },
                    )
                    .unwrap();
                    black_box(total);
                });
            },
        );
    }

    group.finish();
}

fn bench_apply_delta(c: &mut Criterion) {
    let mut group = c.benchmark_group("apply_delta");

    // Exercises both decode_copy_params AND the output buffer reserve path.
    let base_len = 65536;
    let base = vec![0xA5u8; base_len];
    let n_copies = 50;
    let copy_size = 1024;
    let delta = build_copy_heavy_delta(base_len, n_copies, copy_size);
    let result_len = n_copies * copy_size;

    group.throughput(Throughput::Bytes(result_len as u64));
    group.bench_function("copy_heavy_50x1024", |b| {
        let mut out = Vec::new();
        b.iter(|| {
            pack_inflate::apply_delta(black_box(&base), black_box(&delta), &mut out, result_len)
                .unwrap();
            black_box(out.len());
        });
    });

    group.finish();
}

fn bench_inflate_limited(c: &mut Criterion) {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut group = c.benchmark_group("inflate_limited");

    // Create a zlib-compressed payload of known size.
    for &size in &[1024usize, 16384, 65536] {
        let original = vec![0x42u8; size];

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&original).unwrap();
        let compressed = encoder.finish().unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("uniform", size),
            &compressed,
            |b, compressed| {
                let mut out = Vec::new();
                b.iter(|| {
                    pack_inflate::inflate_limited(black_box(compressed), &mut out, size).unwrap();
                    black_box(out.len());
                });
            },
        );
    }

    group.finish();
}

fn bench_tls_overhead(c: &mut Criterion) {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut group = c.benchmark_group("inflate_tls_overhead");

    // Use a tiny payload (64 bytes) so decompression is fast
    // and TLS lookup overhead is a larger fraction of total time.
    let original = vec![0x42u8; 64];
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&original).unwrap();
    let compressed = encoder.finish().unwrap();

    group.throughput(Throughput::Elements(1)); // measure calls/sec, not bytes

    // Thread-local path: inflate_limited uses INFLATE_SCRATCH TLS
    group.bench_function("thread_local", |b| {
        let mut out = Vec::new();
        b.iter(|| {
            pack_inflate::inflate_limited(black_box(&compressed), &mut out, 64).unwrap();
            black_box(out.len());
        });
    });

    // Caller-provided path: inflate_limited_with bypasses TLS
    group.bench_function("caller_provided", |b| {
        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        b.iter(|| {
            pack_inflate::inflate_limited_with(&mut de, black_box(&compressed), &mut out, 64)
                .unwrap();
            black_box(out.len());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_apply_delta_into,
    bench_apply_delta,
    bench_inflate_limited,
    bench_tls_overhead,
);
criterion_main!(benches);
