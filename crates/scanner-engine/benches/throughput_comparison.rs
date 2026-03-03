//! Throughput Comparison Benchmark
//!
//! Compares throughput at each layer of the scanning stack to identify bottlenecks.
//!
//! # Layers
//! 1. Theoretical max (memchr) - ~80-100 GiB/s
//! 2. Raw Vectorscan - ~30 GiB/s
//! 3. Minimal engine (1 impossible rule) - ~12-45 GiB/s
//! 4. Full gitleaks engine - ~170-500 MiB/s
//!
//! # Running
//! ```bash
//! cargo bench --bench throughput_comparison
//! ```

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use scanner_engine::{
    AnchorPolicy, Engine, RuleSpec, Tuning, ValidatorKind, demo_engine, demo_tuning,
};

const BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

// ============================================================================
// Data Generation
// ============================================================================

fn gen_clean_ascii(size: usize) -> Vec<u8> {
    let mut state = 0x12345678u64;
    let mut buf = vec![0u8; size];
    for b in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = b'a' + ((state & 0xFF) % 26) as u8;
    }
    for i in (80..buf.len()).step_by(80) {
        buf[i] = b'\n';
    }
    buf
}

fn gen_random_bytes(size: usize) -> Vec<u8> {
    let mut state = 0x87654321u64;
    let mut buf = vec![0u8; size];
    for b in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = (state & 0xFF) as u8;
    }
    buf
}

fn gen_realistic_source_code(size: usize) -> Vec<u8> {
    // Simulate realistic source code with various patterns
    let patterns = [
        b"function processData(input) {\n".as_slice(),
        b"  const result = await fetch('/api/data');\n".as_slice(),
        b"  if (result.status === 200) {\n".as_slice(),
        b"    return result.json();\n".as_slice(),
        b"  }\n".as_slice(),
        b"  throw new Error('Failed to fetch');\n".as_slice(),
        b"}\n\n".as_slice(),
        b"// Configuration\n".as_slice(),
        b"const config = {\n".as_slice(),
        b"  apiUrl: 'https://api.example.com',\n".as_slice(),
        b"  timeout: 5000,\n".as_slice(),
        b"  retries: 3,\n".as_slice(),
        b"};\n\n".as_slice(),
        b"export default config;\n".as_slice(),
    ];

    let mut buf = Vec::with_capacity(size);
    let mut idx = 0;
    while buf.len() < size {
        buf.extend_from_slice(patterns[idx % patterns.len()]);
        idx += 1;
    }
    buf.truncate(size);
    buf
}

// ============================================================================
// Benchmarks
// ============================================================================

fn bench_throughput_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_stack");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));
    group.sample_size(50);

    let ascii = gen_clean_ascii(BUFFER_SIZE);
    let random = gen_random_bytes(BUFFER_SIZE);
    let realistic = gen_realistic_source_code(BUFFER_SIZE);

    // Layer 1: Theoretical max (memchr)
    group.bench_function("L1_memchr_ascii", |b| {
        b.iter(|| {
            let count = memchr::memchr_iter(b'Z', black_box(&ascii)).count();
            black_box(count)
        })
    });

    group.bench_function("L1_memchr_random", |b| {
        b.iter(|| {
            let count = memchr::memchr_iter(0xFF, black_box(&random)).count();
            black_box(count)
        })
    });

    // Layer 2: Raw Vectorscan (single impossible pattern)
    let tuning = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };

    let impossible_rule = RuleSpec {
        name: "impossible",
        anchors: &[b"ZZZZZZZZ"],
        radius: 64,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(&[b"ZZZZZZZZ"]),
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: None,
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: regex::bytes::Regex::new(r"ZZZZZZZZ[A-Z]{32}").unwrap(),
    };

    let minimal_engine = Engine::new_with_anchor_policy(
        vec![impossible_rule],
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut minimal_scratch = minimal_engine.new_scratch();

    group.bench_function("L2_minimal_engine_ascii", |b| {
        b.iter(|| {
            let hits = minimal_engine.scan_chunk(black_box(&ascii), &mut minimal_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("L2_minimal_engine_random", |b| {
        b.iter(|| {
            let hits = minimal_engine.scan_chunk(black_box(&random), &mut minimal_scratch);
            black_box(hits.len())
        })
    });

    // Layer 3: Full gitleaks engine
    let full_engine = demo_engine();
    let mut full_scratch = full_engine.new_scratch();

    group.bench_function("L3_gitleaks_ascii", |b| {
        b.iter(|| {
            let hits = full_engine.scan_chunk(black_box(&ascii), &mut full_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("L3_gitleaks_random", |b| {
        b.iter(|| {
            let hits = full_engine.scan_chunk(black_box(&random), &mut full_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("L3_gitleaks_realistic", |b| {
        b.iter(|| {
            let hits = full_engine.scan_chunk(black_box(&realistic), &mut full_scratch);
            black_box(hits.len())
        })
    });

    group.finish();
}

fn bench_bottleneck_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("bottleneck_analysis");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));
    group.sample_size(30);

    let ascii = gen_clean_ascii(BUFFER_SIZE);

    // Compare demo_engine configurations
    // demo_engine() uses derived anchors by default, so we just test the full engine
    let full_engine = demo_engine();
    let mut full_scratch = full_engine.new_scratch();

    group.bench_function("gitleaks_full_config", |b| {
        b.iter(|| {
            let hits = full_engine.scan_chunk(black_box(&ascii), &mut full_scratch);
            black_box(hits.len())
        })
    });

    // Test with a minimal config engine (no transforms, no utf16)
    let tuning_minimal = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };

    // Create a simple test pattern to measure vectorscan overhead alone
    let simple_rules: Vec<RuleSpec> = (0..50)
        .map(|i| {
            let prefix = format!("PREFIX{i:02}_");
            let anchor: &'static [u8] = Box::leak(prefix.clone().into_bytes().into_boxed_slice());
            let anchors: &'static [&'static [u8]] = Box::leak(Box::new([anchor]));

            RuleSpec {
                name: Box::leak(format!("test_rule_{i}").into_boxed_str()),
                anchors,
                radius: 64,
                validator: ValidatorKind::None,
                two_phase: None,
                must_contain: None,
                keywords_any: Some(anchors),
                value_suppressors_any: None,
                entropy: None,
                char_class: None,
                local_context: None,
                secret_group: None,
                min_confidence: None,
                offline_validation: None,
                uuid_format_secret: false,
                re: regex::bytes::Regex::new(&format!(r"{prefix}[A-Za-z0-9]{{20}}")).unwrap(),
            }
        })
        .collect();

    let simple_engine = Engine::new_with_anchor_policy(
        simple_rules,
        vec![],
        tuning_minimal,
        AnchorPolicy::ManualOnly,
    );
    let mut simple_scratch = simple_engine.new_scratch();

    group.bench_function("simple_50_rules_ascii", |b| {
        b.iter(|| {
            let hits = simple_engine.scan_chunk(black_box(&ascii), &mut simple_scratch);
            black_box(hits.len())
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_throughput_comparison,
    bench_bottleneck_analysis
);
criterion_main!(benches);
