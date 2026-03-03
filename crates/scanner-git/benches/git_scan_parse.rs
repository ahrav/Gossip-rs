//! Criterion benchmarks for git_scan parsing: tree entry iteration, path
//! classification, and commit header parsing.
//!
//! ## Benchmark groups
//!
//! - **Q1**: `tree_entry::parse_entry` — memchr-accelerated delimiter scan
//! - **Q2**: `classify_path` + `is_nonscannable` — path policy hot path
//! - **Q4 + Q5**: `hex_digit` and `parse_unix_timestamp` via `parse_commit`
//!
//! Usage:
//!   cargo bench --bench git_scan_parse -- --save-baseline before
//!   # ... apply changes ...
//!   cargo bench --bench git_scan_parse -- --baseline before

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use scanner_git::commit_parse::{parse_commit, CommitParseLimits};
use scanner_git::object_id::ObjectFormat;
use scanner_git::path_policy::classify_path;
use scanner_git::tree_entry::TreeEntryIter;

// ---------------------------------------------------------------------------
// Q1: tree_entry parse_entry — memchr vs scalar
// ---------------------------------------------------------------------------

fn make_tree_entries(count: usize, name_len: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    for i in 0..count {
        // mode
        buf.extend_from_slice(b"100644 ");
        // name: pad with 'a' bytes, suffix with index to make unique
        let suffix = format!("{i:06}");
        let pad = name_len.saturating_sub(suffix.len());
        buf.extend(std::iter::repeat_n(b'a', pad));
        buf.extend_from_slice(suffix.as_bytes());
        // NUL
        buf.push(0);
        // 20-byte OID
        let mut oid = [0u8; 20];
        oid[0..4].copy_from_slice(&(i as u32).to_le_bytes());
        buf.extend_from_slice(&oid);
    }
    buf
}

fn bench_parse_entry(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_entry");
    for &name_len in &[8, 32, 64] {
        let entries = make_tree_entries(10_000, name_len);
        group.throughput(Throughput::Elements(10_000));
        group.bench_with_input(
            BenchmarkId::new("iter_all", name_len),
            &entries,
            |b, data| {
                b.iter(|| {
                    let iter = TreeEntryIter::new(black_box(data), 20);
                    let mut count = 0u64;
                    for entry in iter {
                        let _ = black_box(entry.unwrap());
                        count += 1;
                    }
                    count
                })
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Q2: classify_path + is_nonscannable
// ---------------------------------------------------------------------------

fn bench_classify_path(c: &mut Criterion) {
    let paths: Vec<&[u8]> = vec![
        b"src/main.rs",
        b"vendor/third_party/lib/utils.go",
        b"tests/__tests__/deep/nested/component_test.py",
        b"assets/images/logo.png",
        b"generated/proto/service.pb.go",
        b"lib/internal/core/scanner.cpp",
        b"data/blob.xyz",
        b"node_modules/lodash/index.js",
        b"build/dist/out/target/release/binary.wasm",
        b"src/git_scan/tree_entry.rs",
    ];

    let mut group = c.benchmark_group("classify_path");
    group.throughput(Throughput::Elements(paths.len() as u64));
    group.bench_function("classify_batch", |b| {
        b.iter(|| {
            let mut bits = 0u16;
            for path in &paths {
                bits |= classify_path(black_box(path)).bits();
            }
            bits
        })
    });
    group.bench_function("is_nonscannable_batch", |b| {
        b.iter(|| {
            let mut count = 0u32;
            for path in &paths {
                if classify_path(black_box(path)).is_nonscannable() {
                    count += 1;
                }
            }
            count
        })
    });
    group.bench_function("classify_then_exclude", |b| {
        b.iter(|| {
            let mut bits = 0u16;
            let mut excluded = 0u32;
            for path in &paths {
                let class = classify_path(black_box(path));
                bits |= class.bits();
                if class.contains(scanner_git::PathClass::BINARY) {
                    excluded += 1;
                }
            }
            (bits, excluded)
        })
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Q4 + Q5: hex_digit and parse_unix_timestamp (via parse_commit)
// ---------------------------------------------------------------------------

fn make_test_commit() -> Vec<u8> {
    let tree_hex = "1234567890abcdef1234567890abcdef12345678";
    let parent_hex = "abcdef1234567890abcdef1234567890abcdef12";
    let mut buf = Vec::new();
    buf.extend_from_slice(b"tree ");
    buf.extend_from_slice(tree_hex.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(b"parent ");
    buf.extend_from_slice(parent_hex.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(b"author Author Name <author@example.com> 1700000000 +0000\n");
    buf.extend_from_slice(b"committer Committer Name <committer@example.com> 1700000001 +0000\n");
    buf.push(b'\n');
    buf.extend_from_slice(b"Commit message body\n");
    buf
}

fn bench_parse_commit(c: &mut Criterion) {
    let data = make_test_commit();
    let limits = CommitParseLimits::default();

    let mut group = c.benchmark_group("parse_commit");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("single_parent", |b| {
        b.iter(|| parse_commit(black_box(&data), ObjectFormat::Sha1, &limits).unwrap())
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_parse_entry,
    bench_classify_path,
    bench_parse_commit,
);
criterion_main!(benches);
