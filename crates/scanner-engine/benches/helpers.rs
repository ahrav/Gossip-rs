use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use scanner_engine::{
    bench_build_entropy_state, bench_build_merge_ranges_state, bench_build_utf16_decode_state,
    bench_contains_all_memmem, bench_contains_any_memmem, bench_decode_utf16le_with_state,
    bench_entropy_gate_passes_with_state, bench_extract_secret_span_locs, bench_hash128,
    bench_map_utf16_decoded_offset, bench_merge_ranges_load, bench_merge_ranges_run,
    bench_pack_patterns_raw, bench_shannon_entropy_with_state,
};

// ---------------------------------------------------------------------------
// Deterministic PRNG for reproducible data
// ---------------------------------------------------------------------------

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
}

fn make_random(len: usize, seed: u64) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    XorShift64::new(seed).fill_bytes(&mut buf);
    buf
}

fn make_low_entropy(len: usize) -> Vec<u8> {
    // Repeating pattern of 4 bytes — very low entropy.
    (0..len).map(|i| b"abcd"[i % 4]).collect()
}

fn make_ascii_utf16le(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(b);
        out.push(0);
    }
    out
}

fn make_mixed_utf16le(len: usize) -> Vec<u8> {
    // Mix of ASCII, BMP, and a few surrogates.
    let mut out = Vec::with_capacity(len);
    let mut rng = XorShift64::new(0xdead_cafe);
    while out.len() + 4 <= len {
        let v = rng.next_u64();
        if v.is_multiple_of(8) && out.len() + 4 <= len {
            // Surrogate pair: U+10000
            out.extend_from_slice(&[0x00, 0xD8, 0x00, 0xDC]);
        } else {
            // BMP character
            let ch = ((v >> 8) & 0x7F) as u8;
            out.push(ch.max(0x20));
            out.push(0);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// contains_any_memmem / contains_all_memmem
// ---------------------------------------------------------------------------

fn bench_memmem(c: &mut Criterion) {
    let hay = make_random(4096, 0x1234);

    for &needle_count in &[1usize, 4, 16] {
        let patterns: Vec<&[u8]> = (0..needle_count)
            .map(|i| {
                // Needles that do NOT appear in random data (high bytes).
                let start = i * 4;
                let end = start + 4;
                &b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"[start..end]
            })
            .collect();
        let packed = bench_pack_patterns_raw(&patterns);

        let mut group = c.benchmark_group(format!("contains_any_memmem/{}_needles", needle_count));
        group.throughput(Throughput::Bytes(hay.len() as u64));
        group.bench_function("random_hay", |b| {
            b.iter(|| bench_contains_any_memmem(black_box(&hay), black_box(&packed)))
        });
        group.finish();

        let mut group = c.benchmark_group(format!("contains_all_memmem/{}_needles", needle_count));
        group.throughput(Throughput::Bytes(hay.len() as u64));
        group.bench_function("random_hay", |b| {
            b.iter(|| bench_contains_all_memmem(black_box(&hay), black_box(&packed)))
        });
        group.finish();
    }
}

// ---------------------------------------------------------------------------
// shannon_entropy_bits_per_byte / entropy_gate_passes
// ---------------------------------------------------------------------------

fn bench_entropy(c: &mut Criterion) {
    let sizes = [64usize, 256, 4096];
    let max_len = 4096;

    let mut group = c.benchmark_group("shannon_entropy");
    for &sz in &sizes {
        let random = make_random(sz, 0xabcd);
        let low = make_low_entropy(sz);

        group.throughput(Throughput::Bytes(sz as u64));
        let mut random_state = bench_build_entropy_state(max_len);
        group.bench_with_input(BenchmarkId::new("random", sz), &random, |b, data| {
            b.iter(|| bench_shannon_entropy_with_state(black_box(data), &mut random_state))
        });
        let mut low_state = bench_build_entropy_state(max_len);
        group.bench_with_input(BenchmarkId::new("low_entropy", sz), &low, |b, data| {
            b.iter(|| bench_shannon_entropy_with_state(black_box(data), &mut low_state))
        });
    }
    group.finish();

    let mut group = c.benchmark_group("entropy_gate_passes");
    for &sz in &sizes {
        let random = make_random(sz, 0xabcd);
        let low = make_low_entropy(sz);

        group.throughput(Throughput::Bytes(sz as u64));
        let mut random_state = bench_build_entropy_state(max_len);
        group.bench_with_input(BenchmarkId::new("random", sz), &random, |b, data| {
            b.iter(|| {
                bench_entropy_gate_passes_with_state(3.0, 16, black_box(data), &mut random_state)
            })
        });
        let mut low_state = bench_build_entropy_state(max_len);
        group.bench_with_input(BenchmarkId::new("low_entropy", sz), &low, |b, data| {
            b.iter(|| {
                bench_entropy_gate_passes_with_state(3.0, 16, black_box(data), &mut low_state)
            })
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// merge_ranges_with_gap_sorted
// ---------------------------------------------------------------------------

fn bench_merge_ranges_group(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge_ranges");

    for &count in &[16usize, 64, 256] {
        // Non-overlapping ranges spaced by gap+1 (no merging).
        let no_merge: Vec<(u32, u32)> =
            (0..count as u32).map(|i| (i * 200, i * 200 + 50)).collect();
        // Overlapping ranges (all merge into one).
        let all_merge: Vec<(u32, u32)> = (0..count as u32).map(|i| (i * 10, i * 10 + 30)).collect();

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::new("no_merge", count), &no_merge, |b, data| {
            b.iter_batched(
                || {
                    let mut state = bench_build_merge_ranges_state(data.len());
                    bench_merge_ranges_load(&mut state, data);
                    state
                },
                |mut state| bench_merge_ranges_run(black_box(&mut state), 32),
                BatchSize::SmallInput,
            )
        });
        group.bench_with_input(
            BenchmarkId::new("all_merge", count),
            &all_merge,
            |b, data| {
                b.iter_batched(
                    || {
                        let mut state = bench_build_merge_ranges_state(data.len());
                        bench_merge_ranges_load(&mut state, data);
                        state
                    },
                    |mut state| bench_merge_ranges_run(black_box(&mut state), 32),
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// decode_utf16le_to_buf
// ---------------------------------------------------------------------------

fn bench_utf16_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_utf16le");

    for &byte_len in &[256usize, 4096] {
        let ascii_text = vec![b'A'; byte_len / 2];
        let ascii_u16 = make_ascii_utf16le(&ascii_text);
        let mixed_u16 = make_mixed_utf16le(byte_len);

        let max_out = byte_len * 2; // generous cap

        group.throughput(Throughput::Bytes(byte_len as u64));
        let mut ascii_state = bench_build_utf16_decode_state(max_out);
        group.bench_with_input(
            BenchmarkId::new("ascii", byte_len),
            &ascii_u16,
            |b, data| b.iter(|| bench_decode_utf16le_with_state(black_box(data), &mut ascii_state)),
        );
        let mut mixed_state = bench_build_utf16_decode_state(max_out);
        group.bench_with_input(
            BenchmarkId::new("mixed", byte_len),
            &mixed_u16,
            |b, data| b.iter(|| bench_decode_utf16le_with_state(black_box(data), &mut mixed_state)),
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// map_utf16_decoded_offset
// ---------------------------------------------------------------------------

fn bench_utf16_offset(c: &mut Criterion) {
    let mut group = c.benchmark_group("map_utf16_decoded_offset");

    for &byte_len in &[256usize, 4096] {
        let ascii_text = vec![b'A'; byte_len / 2];
        let ascii_u16 = make_ascii_utf16le(&ascii_text);

        // Offset at 25% and 75% of decoded length.
        let decoded_len = ascii_text.len(); // ASCII: 1 byte per code unit
        let off_25 = decoded_len / 4;
        let off_75 = decoded_len * 3 / 4;

        group.throughput(Throughput::Bytes(byte_len as u64));
        group.bench_with_input(
            BenchmarkId::new("25pct", byte_len),
            &ascii_u16,
            |b, data| b.iter(|| bench_map_utf16_decoded_offset(black_box(data), off_25, true)),
        );
        group.bench_with_input(
            BenchmarkId::new("75pct", byte_len),
            &ascii_u16,
            |b, data| b.iter(|| bench_map_utf16_decoded_offset(black_box(data), off_75, true)),
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// extract_secret_span_locs
// ---------------------------------------------------------------------------

fn bench_extract_secret(c: &mut Criterion) {
    let mut group = c.benchmark_group("extract_secret_span_locs");

    // Build regexes with different group counts.
    for &groups in &[1usize, 4, 8] {
        // Build a regex with `groups` capture groups, where group 1 matches.
        let pattern = if groups == 1 {
            r"SECRET([A-Z0-9]{8})".to_string()
        } else {
            // groups-1 non-matching groups then 1 matching group.
            let mut pat = String::from("SECRET");
            for _ in 1..groups {
                pat.push_str("([xyz]?)");
            }
            pat.push_str("([A-Z0-9]{8})");
            pat
        };

        let re = regex::bytes::Regex::new(&pattern).unwrap();
        let hay = b"SECRETABCD1234";
        let mut locs = re.capture_locations();
        re.captures_read(&mut locs, hay);

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::new("groups", groups), &locs, |b, locs| {
            b.iter(|| bench_extract_secret_span_locs(black_box(locs), None))
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// hash128
// ---------------------------------------------------------------------------

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash128");

    for &sz in &[32usize, 256, 4096] {
        let data = make_random(sz, 0xbeef);
        group.throughput(Throughput::Bytes(sz as u64));
        group.bench_with_input(BenchmarkId::new("random", sz), &data, |b, data| {
            b.iter(|| bench_hash128(black_box(data)))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_memmem,
    bench_entropy,
    bench_merge_ranges_group,
    bench_utf16_decode,
    bench_utf16_offset,
    bench_extract_secret,
    bench_hashing,
);
criterion_main!(benches);
