use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use scanner_engine::b64_yara_gate::{Base64YaraGate, Base64YaraGateConfig, GateState};
use scanner_engine::{AnchorMode, demo_engine_with_anchor_mode};

const ENGINE_BUF_LEN: usize = 4 * 1024 * 1024; // 4 MiB
const GATE_BUF_LEN: usize = 1024 * 1024; // 1 MiB

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
            let chunk = buf.len() - i;
            let take = if chunk < 8 { chunk } else { 8 };
            for j in 0..take {
                buf[i + j] = (v & 0xff) as u8;
                v >>= 8;
            }
            i += take;
        }
    }

    fn fill_ascii(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            let v = (self.next_u64() & 0xff) as u8;
            let letter = b'a' + (v % 26);
            *b = letter;
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

fn inject_token(buf: &mut [u8], token: &[u8], stride: usize) {
    if token.is_empty() || stride == 0 || buf.len() < token.len() {
        return;
    }
    let mut i = 1usize;
    while i + token.len() <= buf.len() {
        buf[i..i + token.len()].copy_from_slice(token);
        i = i.saturating_add(stride);
    }
}

fn make_datasets() -> Vec<Dataset> {
    let mut rng = XorShift64::new(0x1234_5678_9abc_def0);

    let mut random = vec![0u8; ENGINE_BUF_LEN];
    rng.fill_bytes(&mut random);

    let mut ascii_hits = vec![0u8; ENGINE_BUF_LEN];
    rng.fill_ascii(&mut ascii_hits);
    let aws = b"AKIAIOSFODNN7EXAMPLE";
    let ghp = b"ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    inject_token(&mut ascii_hits, aws, 4 * 1024);
    inject_token(&mut ascii_hits, ghp, 16 * 1024);

    let mut utf16le_hits = make_utf16_text(ENGINE_BUF_LEN, 0x1111_2222_3333_4444, false);
    inject_token_utf16(&mut utf16le_hits, aws, 4 * 1024, false);
    inject_token_utf16(&mut utf16le_hits, ghp, 16 * 1024, false);

    let mut utf16be_hits = make_utf16_text(ENGINE_BUF_LEN, 0x5555_6666_7777_8888, true);
    inject_token_utf16(&mut utf16be_hits, aws, 4 * 1024, true);
    inject_token_utf16(&mut utf16be_hits, ghp, 16 * 1024, true);

    let encoded = B64_STD.encode(aws);
    let mut b64_hits = Vec::with_capacity(ENGINE_BUF_LEN);
    while b64_hits.len() + encoded.len() < ENGINE_BUF_LEN {
        b64_hits.extend_from_slice(encoded.as_bytes());
        b64_hits.push(b'\n');
    }

    vec![
        Dataset {
            name: "random",
            buf: random,
        },
        Dataset {
            name: "ascii_hits",
            buf: ascii_hits,
        },
        Dataset {
            name: "utf16le_hits",
            buf: utf16le_hits,
        },
        Dataset {
            name: "utf16be_hits",
            buf: utf16be_hits,
        },
        Dataset {
            name: "base64_hits",
            buf: b64_hits,
        },
    ]
}

fn encode_utf16_bytes(input: &[u8], be: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 2);
    for &b in input {
        if be {
            out.push(0);
            out.push(b);
        } else {
            out.push(b);
            out.push(0);
        }
    }
    out
}

fn make_utf16_text(len: usize, seed: u64, be: bool) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut rng = XorShift64::new(seed);
    let code_units = len / 2;
    for i in 0..code_units {
        let v = (rng.next_u64() & 0xff) as u8;
        let letter = b'a' + (v % 26);
        let idx = i * 2;
        if be {
            out[idx] = 0;
            out[idx + 1] = letter;
        } else {
            out[idx] = letter;
            out[idx + 1] = 0;
        }
    }

    if out.len() >= 2 {
        if be {
            out[0] = 0xFE;
            out[1] = 0xFF;
        } else {
            out[0] = 0xFF;
            out[1] = 0xFE;
        }
    }

    out
}

fn inject_token_utf16(buf: &mut [u8], token: &[u8], stride_bytes: usize, be: bool) {
    let stride_units = (stride_bytes / 2).max(1);
    let encoded = encode_utf16_bytes(token, be);
    if encoded.is_empty() || buf.len() < encoded.len() {
        return;
    }

    let mut i = 0usize;
    let max_units = buf.len() / 2;
    while i + token.len() <= max_units {
        let byte_idx = i * 2;
        if byte_idx + encoded.len() > buf.len() {
            break;
        }
        buf[byte_idx..byte_idx + encoded.len()].copy_from_slice(&encoded);
        i = i.saturating_add(stride_units);
    }
}

fn bench_engine_scan(c: &mut Criterion) {
    let datasets = make_datasets();
    let engines = [
        ("manual", demo_engine_with_anchor_mode(AnchorMode::Manual)),
        ("derived", demo_engine_with_anchor_mode(AnchorMode::Derived)),
    ];

    let mut group = c.benchmark_group("engine_scan");
    for (engine_name, engine) in engines {
        let mut scratch = engine.new_scratch();
        for ds in &datasets {
            group.throughput(Throughput::Bytes(ds.buf.len() as u64));
            let id = BenchmarkId::new(engine_name, ds.name);
            group.bench_with_input(id, ds, |b, ds| {
                b.iter(|| {
                    let hits = engine.scan_chunk(black_box(&ds.buf), &mut scratch);
                    black_box(hits.len());
                })
            });
        }
    }
    group.finish();
}

fn bench_baseline(c: &mut Criterion) {
    let mut rng = XorShift64::new(0x0f0e_0d0c_0b0a_0908);
    let mut buf = vec![0u8; ENGINE_BUF_LEN];
    rng.fill_bytes(&mut buf);
    let no_match = vec![b'A'; ENGINE_BUF_LEN];

    let mut group = c.benchmark_group("baseline");
    group.throughput(Throughput::Bytes(buf.len() as u64));
    group.bench_function("linear_sum", |b| {
        b.iter(|| {
            let mut sum = 0u64;
            for &v in buf.iter() {
                sum = sum.wrapping_add(v as u64);
            }
            black_box(sum);
        })
    });
    group.bench_function("memchr_Z", |b| {
        b.iter(|| {
            black_box(memchr::memchr(b'Z', &no_match));
        })
    });
    group.finish();
}

fn bench_base64_gate(c: &mut Criterion) {
    let anchors: [&[u8]; 5] = [b"AKIA", b"ghp_", b"xoxb-", b"glpat-", b"sk_test_"];
    let gate = Base64YaraGate::build(anchors, Base64YaraGateConfig::default());

    let aws = b"AKIAIOSFODNN7EXAMPLE";
    let encoded = B64_STD.encode(aws);
    let mut rng = XorShift64::new(0xfeed_face_cafe_beef);
    let mut noise = vec![0u8; GATE_BUF_LEN];
    rng.fill_base64(&mut noise);
    let mut hits_at_end = noise.clone();
    if encoded.len() <= hits_at_end.len() {
        let start = hits_at_end.len() - encoded.len();
        hits_at_end[start..].copy_from_slice(encoded.as_bytes());
    }

    let mut group = c.benchmark_group("b64_gate");
    group.throughput(Throughput::Bytes(noise.len() as u64));
    group.bench_function("hits_at_end_one_shot", |b| {
        b.iter(|| {
            black_box(gate.hits(black_box(&hits_at_end)));
        })
    });
    group.bench_function("hits_at_end_stream", |b| {
        let mut st = GateState::default();
        b.iter(|| {
            st.reset();
            black_box(gate.scan_with_state(black_box(&hits_at_end), &mut st));
        })
    });
    group.bench_function("noise_one_shot", |b| {
        b.iter(|| {
            black_box(gate.hits(black_box(&noise)));
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_engine_scan,
    bench_baseline,
    bench_base64_gate
);
criterion_main!(benches);
