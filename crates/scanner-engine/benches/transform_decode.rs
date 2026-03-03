use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use scanner_engine::{
    Gate, TransformConfig, TransformId, TransformMode, bench_find_spans_into,
    bench_stream_decode_base64, bench_stream_decode_url,
};
use std::time::Duration;

const BUF_LEN: usize = 4 * 1024 * 1024; // 4 MiB

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let mut v = self.next_u64();
            let take = (buf.len() - i).min(8);
            for j in 0..take {
                buf[i + j] = (v & 0xff) as u8;
                v >>= 8;
            }
            i += take;
        }
    }

    fn fill_base64(&mut self, buf: &mut [u8]) {
        const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for b in buf.iter_mut() {
            let v = (self.next_u64() & 0x3f) as usize;
            *b = ALPH[v];
        }
    }
}

struct Dataset {
    name: &'static str,
    buf: Vec<u8>,
}

struct SizeSweep {
    size: usize,
    random: Vec<u8>,
    urlish: Vec<u8>,
    base64_noise: Vec<u8>,
}

fn make_random(len: usize, seed: u64) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut rng = XorShift64::new(seed);
    rng.fill_bytes(&mut buf);
    buf
}

fn make_base64(len: usize, seed: u64) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut rng = XorShift64::new(seed);
    rng.fill_base64(&mut buf);
    buf
}

fn make_urlish(len: usize) -> Vec<u8> {
    let mut buf = vec![b'a'; len];
    let stride = 64;
    let max = len.saturating_sub(3);
    let mut i = 0usize;
    while i < max {
        buf[i] = b'%';
        buf[i + 1] = b'2';
        buf[i + 2] = b'F';
        i = i.saturating_add(stride);
    }
    buf
}

fn make_size_sweep(sizes: &[usize]) -> Vec<SizeSweep> {
    sizes
        .iter()
        .enumerate()
        .map(|(idx, &size)| SizeSweep {
            size,
            random: make_random(size, 0x1234_5678_9abc_def0 ^ (idx as u64)),
            urlish: make_urlish(size),
            base64_noise: make_base64(size, 0x0f0e_0d0c_0b0a_0908 ^ (idx as u64)),
        })
        .collect()
}

fn url_config(max_spans: usize) -> TransformConfig {
    TransformConfig {
        id: TransformId::UrlPercent,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 16,
        max_spans_per_buffer: max_spans,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }
}

fn b64_config(max_spans: usize) -> TransformConfig {
    TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 32,
        max_spans_per_buffer: max_spans,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }
}

fn bench_transform_spans(c: &mut Criterion) {
    let random = Dataset {
        name: "random",
        buf: make_random(BUF_LEN, 0x1234_5678_9abc_def0),
    };
    let urlish = Dataset {
        name: "urlish",
        buf: make_urlish(BUF_LEN),
    };
    let b64_noise = Dataset {
        name: "base64_noise",
        buf: make_base64(BUF_LEN, 0x0f0e_0d0c_0b0a_0908),
    };

    let url_cfg_limited = url_config(8);
    let url_cfg_unbounded = url_config(1024);
    let b64_cfg_limited = b64_config(8);
    let b64_cfg_unbounded = b64_config(1024);

    let mut spans = Vec::with_capacity(2048);

    let mut url_group = c.benchmark_group("transform_spans_url");
    for ds in [&random, &urlish] {
        url_group.throughput(Throughput::Bytes(ds.buf.len() as u64));
        url_group.bench_with_input(BenchmarkId::new("limited", ds.name), ds, |b, ds| {
            b.iter(|| {
                bench_find_spans_into(&url_cfg_limited, black_box(&ds.buf), &mut spans);
                black_box(spans.len());
            })
        });
        url_group.bench_with_input(BenchmarkId::new("unbounded", ds.name), ds, |b, ds| {
            b.iter(|| {
                bench_find_spans_into(&url_cfg_unbounded, black_box(&ds.buf), &mut spans);
                black_box(spans.len());
            })
        });
    }
    url_group.finish();

    let mut b64_group = c.benchmark_group("transform_spans_b64");
    for ds in [&random, &b64_noise] {
        b64_group.throughput(Throughput::Bytes(ds.buf.len() as u64));
        b64_group.bench_with_input(BenchmarkId::new("limited", ds.name), ds, |b, ds| {
            b.iter(|| {
                bench_find_spans_into(&b64_cfg_limited, black_box(&ds.buf), &mut spans);
                black_box(spans.len());
            })
        });
        b64_group.bench_with_input(BenchmarkId::new("unbounded", ds.name), ds, |b, ds| {
            b.iter(|| {
                bench_find_spans_into(&b64_cfg_unbounded, black_box(&ds.buf), &mut spans);
                black_box(spans.len());
            })
        });
    }
    b64_group.finish();
}

fn bench_size_sweep(c: &mut Criterion) {
    let sizes = [
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
        16 * 1024 * 1024,
        64 * 1024 * 1024,
    ];
    let data = make_size_sweep(&sizes);

    let url_cfg = url_config(4096);
    let b64_cfg = b64_config(4096);
    let mut spans = Vec::with_capacity(2048);

    let mut url_group = c.benchmark_group("size_sweep_url");
    url_group.sample_size(10);
    url_group.measurement_time(Duration::from_secs(3));
    for ds in &data {
        url_group.throughput(Throughput::Bytes(ds.size as u64));
        url_group.bench_with_input(BenchmarkId::new("random", ds.size), ds, |b, ds| {
            b.iter(|| {
                bench_find_spans_into(&url_cfg, black_box(&ds.random), &mut spans);
                black_box(spans.len());
            })
        });
        url_group.bench_with_input(BenchmarkId::new("urlish", ds.size), ds, |b, ds| {
            b.iter(|| {
                bench_find_spans_into(&url_cfg, black_box(&ds.urlish), &mut spans);
                black_box(spans.len());
            })
        });
    }
    url_group.finish();

    let mut b64_group = c.benchmark_group("size_sweep_b64");
    b64_group.sample_size(10);
    b64_group.measurement_time(Duration::from_secs(3));
    for ds in &data {
        b64_group.throughput(Throughput::Bytes(ds.size as u64));
        b64_group.bench_with_input(BenchmarkId::new("random", ds.size), ds, |b, ds| {
            b.iter(|| {
                bench_find_spans_into(&b64_cfg, black_box(&ds.random), &mut spans);
                black_box(spans.len());
            })
        });
        b64_group.bench_with_input(BenchmarkId::new("base64_noise", ds.size), ds, |b, ds| {
            b.iter(|| {
                bench_find_spans_into(&b64_cfg, black_box(&ds.base64_noise), &mut spans);
                black_box(spans.len());
            })
        });
    }
    b64_group.finish();
}

fn bench_decode_url(c: &mut Criterion) {
    // URL-encoded data with varying escape densities
    let dense_escapes = {
        // Every 3 bytes: %XX pattern (100% escape density)
        let mut buf = vec![0u8; BUF_LEN];
        let hex_chars = b"0123456789ABCDEF";
        let mut i = 0;
        let mut h = 0u8;
        while i + 2 < buf.len() {
            buf[i] = b'%';
            buf[i + 1] = hex_chars[(h >> 4) as usize];
            buf[i + 2] = hex_chars[(h & 0x0F) as usize];
            h = h.wrapping_add(1);
            i += 3;
        }
        buf
    };

    let sparse_escapes = {
        // One escape every 64 bytes (typical URL path)
        let mut buf = vec![b'a'; BUF_LEN];
        let mut i = 0;
        while i + 2 < buf.len() {
            buf[i] = b'%';
            buf[i + 1] = b'2';
            buf[i + 2] = b'F';
            i += 64;
        }
        buf
    };

    let mixed_plus = {
        // Mix of %XX and + characters
        let mut buf = vec![b'a'; BUF_LEN];
        let mut i = 0;
        while i + 3 < buf.len() {
            buf[i] = b'%';
            buf[i + 1] = b'2';
            buf[i + 2] = b'0';
            buf[i + 3] = b'+';
            i += 32;
        }
        buf
    };

    let mut group = c.benchmark_group("decode_url");

    group.throughput(Throughput::Bytes(dense_escapes.len() as u64));
    group.bench_function("dense_escapes", |b| {
        b.iter(|| {
            let decoded = bench_stream_decode_url(black_box(&dense_escapes), false);
            black_box(decoded);
        })
    });

    group.throughput(Throughput::Bytes(sparse_escapes.len() as u64));
    group.bench_function("sparse_escapes", |b| {
        b.iter(|| {
            let decoded = bench_stream_decode_url(black_box(&sparse_escapes), false);
            black_box(decoded);
        })
    });

    group.throughput(Throughput::Bytes(mixed_plus.len() as u64));
    group.bench_function("mixed_plus", |b| {
        b.iter(|| {
            let decoded = bench_stream_decode_url(black_box(&mixed_plus), true);
            black_box(decoded);
        })
    });

    group.finish();
}

fn bench_decode_b64(c: &mut Criterion) {
    let mut rng = XorShift64::new(0xdead_beef_cafe_babe);

    // Valid base64 data (no whitespace)
    let valid_b64 = {
        let mut buf = vec![0u8; BUF_LEN];
        rng.fill_base64(&mut buf);
        buf
    };

    // Base64 with embedded newlines (MIME-style, 76 chars per line)
    let mime_b64 = {
        let mut buf = Vec::with_capacity(BUF_LEN + BUF_LEN / 76);
        let mut tmp = vec![0u8; BUF_LEN];
        rng.fill_base64(&mut tmp);
        for chunk in tmp.chunks(76) {
            buf.extend_from_slice(chunk);
            buf.push(b'\n');
        }
        buf
    };

    // Base64 with padding
    let padded_b64 = {
        // Generate valid base64 with proper padding
        let mut buf = vec![0u8; BUF_LEN];
        rng.fill_base64(&mut buf);
        // Ensure proper 4-byte alignment with padding
        let aligned_len = (buf.len() / 4) * 4;
        buf.truncate(aligned_len);
        // Add some padding cases
        if aligned_len >= 4 {
            buf[aligned_len - 1] = b'=';
            buf[aligned_len - 2] = b'=';
        }
        buf
    };

    let mut group = c.benchmark_group("decode_b64");

    group.throughput(Throughput::Bytes(valid_b64.len() as u64));
    group.bench_function("valid_continuous", |b| {
        b.iter(|| {
            let decoded = bench_stream_decode_base64(black_box(&valid_b64));
            black_box(decoded);
        })
    });

    group.throughput(Throughput::Bytes(mime_b64.len() as u64));
    group.bench_function("mime_with_newlines", |b| {
        b.iter(|| {
            let decoded = bench_stream_decode_base64(black_box(&mime_b64));
            black_box(decoded);
        })
    });

    group.throughput(Throughput::Bytes(padded_b64.len() as u64));
    group.bench_function("with_padding", |b| {
        b.iter(|| {
            let decoded = bench_stream_decode_base64(black_box(&padded_b64));
            black_box(decoded);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_transform_spans,
    bench_size_sweep,
    bench_decode_url,
    bench_decode_b64
);
criterion_main!(benches);
