//! Vectorscan Overhead Analysis
//!
//! This benchmark suite isolates the different layers between raw SIMD throughput
//! and the full scanner to identify where overhead comes from. Use these results
//! to understand the performance cost of each abstraction layer.
//!
//! # Layers Measured
//!
//! | Layer | What it measures | Expected throughput |
//! |-------|------------------|---------------------|
//! | 1. memchr | Pure SIMD byte scanning | ~80 GB/s (memory bandwidth ceiling) |
//! | 2. Raw Vectorscan | hs_scan FFI + automaton traversal | 40-60 GB/s |
//! | 3. Minimal Engine | Scanner wrapper + scratch management | 30-50 GB/s |
//! | 4. Full Engine | Complete pipeline with all rules | 5-30 GB/s |
//!
//! # Interpreting Results
//!
//! The gap between adjacent layers reveals where optimization effort should focus:
//!
//! - **Layer 1 -> 2**: FFI call overhead + DFA state machine vs. simple SIMD scan
//! - **Layer 2 -> 3**: Rust wrapper overhead, scratch allocation, callback dispatch
//! - **Layer 3 -> 4**: Rule complexity, transform detection, validator execution
//!
//! If Layer 2 is much slower than Layer 1, investigate pattern complexity.
//! If Layer 3 is much slower than Layer 2, the Rust wrapper has overhead.
//! If Layer 4 is much slower than Layer 3, focus on rule optimization.
//!
//! # Running
//!
//! ```bash
//! cargo bench --bench vectorscan_overhead
//!
//! # Specific layer
//! cargo bench --bench vectorscan_overhead -- layer1
//! cargo bench --bench vectorscan_overhead -- layer2
//! cargo bench --bench vectorscan_overhead -- layer3
//! cargo bench --bench vectorscan_overhead -- layer4
//! ```

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use scanner_engine::{AnchorPolicy, Engine, RuleSpec, Tuning, ValidatorKind};
use std::ffi::CString;

// ============================================================================
// Configuration
// ============================================================================

const BUFFER_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

// ============================================================================
// Data Generation
// ============================================================================

// NOTE: These generators duplicate code from scanner_throughput.rs intentionally.
// Benchmark files should be self-contained to avoid cross-benchmark dependencies
// that could cause subtle measurement artifacts from shared code paths.

/// Generate random bytes with xorshift64 PRNG.
fn gen_random_bytes(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut buf = vec![0u8; size];
    for chunk in buf.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        let len = chunk.len().min(8);
        chunk[..len].copy_from_slice(&bytes[..len]);
    }
    buf
}

/// Generate lowercase ASCII with periodic newlines.
fn gen_clean_ascii(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut buf = vec![0u8; size];
    for b in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = b'a' + ((state & 0xFF) % 26) as u8;
    }
    // Add newlines
    for i in (80..buf.len()).step_by(80) {
        buf[i] = b'\n';
    }
    buf
}

// ============================================================================
// Layer 1: memchr Baseline
// ============================================================================

fn bench_memchr_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer1_memchr");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let random = gen_random_bytes(BUFFER_SIZE, 0x5678);

    group.bench_function("ascii_not_found", |b| {
        b.iter(|| black_box(memchr::memchr(0xFF, black_box(&ascii))))
    });

    group.bench_function("random_first_occurrence", |b| {
        b.iter(|| black_box(memchr::memchr(0x00, black_box(&random))))
    });

    group.bench_function("ascii_memchr2", |b| {
        b.iter(|| black_box(memchr::memchr2(0xFE, 0xFF, black_box(&ascii))))
    });

    group.bench_function("ascii_count_newlines", |b| {
        b.iter(|| black_box(memchr::memchr_iter(b'\n', black_box(&ascii)).count()))
    });

    group.finish();
}

// ============================================================================
// Layer 2: Raw Vectorscan (Minimal Callback)
// ============================================================================

fn bench_raw_vectorscan(c: &mut Criterion) {
    use vectorscan_rs_sys as vs;

    let mut group = c.benchmark_group("layer2_raw_vectorscan");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let random = gen_random_bytes(BUFFER_SIZE, 0x5678);

    let pattern = CString::new(r"\xFF\xFE\xFD").unwrap();
    let patterns = [pattern.as_ptr()];
    let flags = [vs::HS_FLAG_SINGLEMATCH];
    let ids = [0u32];

    let mut db: *mut vs::hs_database_t = std::ptr::null_mut();
    let mut compile_err: *mut vs::hs_compile_error_t = std::ptr::null_mut();

    // SAFETY: FFI call to Vectorscan. All pointer arguments are valid.
    let rc = unsafe {
        vs::hs_compile_multi(
            patterns.as_ptr(),
            flags.as_ptr(),
            ids.as_ptr(),
            1,
            vs::HS_MODE_BLOCK,
            std::ptr::null(),
            &mut db,
            &mut compile_err,
        )
    };
    assert_eq!(rc, vs::HS_SUCCESS as i32, "hs_compile_multi failed");

    let mut scratch: *mut vs::hs_scratch_t = std::ptr::null_mut();
    // SAFETY: `db` is a valid compiled database.
    let rc = unsafe { vs::hs_alloc_scratch(db, &mut scratch) };
    assert_eq!(rc, vs::HS_SUCCESS as i32, "hs_alloc_scratch failed");

    extern "C" fn count_callback(
        _id: std::ffi::c_uint,
        _from: u64,
        _to: u64,
        _flags: std::ffi::c_uint,
        ctx: *mut std::ffi::c_void,
    ) -> std::ffi::c_int {
        // SAFETY: ctx is a valid *mut u64 pointing to a local variable.
        unsafe {
            let count = ctx as *mut u64;
            *count += 1;
        }
        0
    }

    group.bench_function("single_pattern_ascii", |b| {
        let mut count: u64 = 0;
        b.iter(|| {
            count = 0;
            // SAFETY: `db` and `scratch` are valid.
            let rc = unsafe {
                vs::hs_scan(
                    db,
                    ascii.as_ptr() as *const std::ffi::c_char,
                    ascii.len() as u32,
                    0,
                    scratch,
                    Some(count_callback),
                    (&mut count as *mut u64) as *mut std::ffi::c_void,
                )
            };
            assert_eq!(rc, vs::HS_SUCCESS as i32);
            black_box(count)
        })
    });

    group.bench_function("single_pattern_random", |b| {
        let mut count: u64 = 0;
        b.iter(|| {
            count = 0;
            // SAFETY: `db` and `scratch` are valid.
            let rc = unsafe {
                vs::hs_scan(
                    db,
                    random.as_ptr() as *const std::ffi::c_char,
                    random.len() as u32,
                    0,
                    scratch,
                    Some(count_callback),
                    (&mut count as *mut u64) as *mut std::ffi::c_void,
                )
            };
            assert_eq!(rc, vs::HS_SUCCESS as i32);
            black_box(count)
        })
    });

    // Multi-pattern
    let patterns_multi: Vec<CString> = (0..10)
        .map(|i| CString::new(format!(r"\xFF\xFE\xFD{:02x}", i)).unwrap())
        .collect();
    let pattern_ptrs: Vec<*const std::ffi::c_char> =
        patterns_multi.iter().map(|p| p.as_ptr()).collect();
    let flags_multi: Vec<u32> = vec![vs::HS_FLAG_SINGLEMATCH; 10];
    let ids_multi: Vec<u32> = (0..10).collect();

    let mut db_multi: *mut vs::hs_database_t = std::ptr::null_mut();
    // SAFETY: FFI call with valid arrays.
    let rc = unsafe {
        vs::hs_compile_multi(
            pattern_ptrs.as_ptr(),
            flags_multi.as_ptr(),
            ids_multi.as_ptr(),
            10,
            vs::HS_MODE_BLOCK,
            std::ptr::null(),
            &mut db_multi,
            &mut compile_err,
        )
    };
    assert_eq!(rc, vs::HS_SUCCESS as i32);

    let mut scratch_multi: *mut vs::hs_scratch_t = std::ptr::null_mut();
    // SAFETY: `db_multi` is a valid compiled database.
    let rc = unsafe { vs::hs_alloc_scratch(db_multi, &mut scratch_multi) };
    assert_eq!(rc, vs::HS_SUCCESS as i32);

    group.bench_function("10_patterns_ascii", |b| {
        let mut count: u64 = 0;
        b.iter(|| {
            count = 0;
            // SAFETY: `db_multi` and `scratch_multi` are valid.
            let rc = unsafe {
                vs::hs_scan(
                    db_multi,
                    ascii.as_ptr() as *const std::ffi::c_char,
                    ascii.len() as u32,
                    0,
                    scratch_multi,
                    Some(count_callback),
                    (&mut count as *mut u64) as *mut std::ffi::c_void,
                )
            };
            assert_eq!(rc, vs::HS_SUCCESS as i32);
            black_box(count)
        })
    });

    // SAFETY: All pointers were successfully allocated and have not been freed.
    unsafe {
        vs::hs_free_scratch(scratch);
        vs::hs_free_scratch(scratch_multi);
        vs::hs_free_database(db);
        vs::hs_free_database(db_multi);
    }

    group.finish();
}

// ============================================================================
// Layer 3: Minimal Scanner Engine
// ============================================================================

fn bench_minimal_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer3_minimal_engine");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let random = gen_random_bytes(BUFFER_SIZE, 0x5678);

    let rules = vec![RuleSpec {
        name: "impossible",
        anchors: &[b"\xFF\xFE\xFD\xFC"],
        radius: 64,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: None,
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: regex::bytes::Regex::new(r"\xFF\xFE\xFD\xFC[a-z]{10}").unwrap(),
    }];

    let tuning = Tuning {
        max_transform_depth: 0,
        ..scanner_engine::demo_tuning()
    };

    let engine =
        Engine::new_with_anchor_policy(rules, vec![], tuning.clone(), AnchorPolicy::ManualOnly);
    let mut scratch = engine.new_scratch();

    group.bench_function("1_rule_ascii", |b| {
        b.iter(|| {
            let hits = engine.scan_chunk(black_box(&ascii), &mut scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("1_rule_random", |b| {
        b.iter(|| {
            let hits = engine.scan_chunk(black_box(&random), &mut scratch);
            black_box(hits.len())
        })
    });

    let rules_10: Vec<RuleSpec> = (0..10)
        .map(|i| RuleSpec {
            name: Box::leak(format!("impossible_{i}").into_boxed_str()),
            anchors: &[b"\xFF\xFE\xFD\xFC"],
            radius: 64,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: None,
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re: regex::bytes::Regex::new(&format!(r"\xFF\xFE\xFD\xFC{i:02}[a-z]{{10}}")).unwrap(),
        })
        .collect();

    let engine_10 =
        Engine::new_with_anchor_policy(rules_10, vec![], tuning.clone(), AnchorPolicy::ManualOnly);
    let mut scratch_10 = engine_10.new_scratch();

    group.bench_function("10_rules_ascii", |b| {
        b.iter(|| {
            let hits = engine_10.scan_chunk(black_box(&ascii), &mut scratch_10);
            black_box(hits.len())
        })
    });

    group.bench_function("10_rules_random", |b| {
        b.iter(|| {
            let hits = engine_10.scan_chunk(black_box(&random), &mut scratch_10);
            black_box(hits.len())
        })
    });

    group.finish();
}

// ============================================================================
// Layer 4: Full Engine Comparison
// ============================================================================

fn bench_full_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("layer4_full_engine");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let random = gen_random_bytes(BUFFER_SIZE, 0x5678);

    let engine = scanner_engine::demo_engine_with_anchor_mode(scanner_engine::AnchorMode::Derived);
    let mut scratch = engine.new_scratch();

    group.bench_function("full_gitleaks_ascii", |b| {
        b.iter(|| {
            let hits = engine.scan_chunk(black_box(&ascii), &mut scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("full_gitleaks_random", |b| {
        b.iter(|| {
            let hits = engine.scan_chunk(black_box(&random), &mut scratch);
            black_box(hits.len())
        })
    });

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    overhead_benches,
    bench_memchr_baseline,
    bench_raw_vectorscan,
    bench_minimal_engine,
    bench_full_engine,
);

criterion_main!(overhead_benches);
