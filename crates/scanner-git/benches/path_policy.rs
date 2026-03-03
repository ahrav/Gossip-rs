//! Benchmarks for `classify_path` and `ext_in_skip_set`.
//!
//! These functions sit on the critical path of both git-scan tree-diff and
//! local-fs file dispatch — every candidate blob/file passes through them.
//!
//! Representative path distribution:
//! - Source files (common hit)
//! - Binary files (skip-set hit)
//! - Lock files (lock-table hit)
//! - Unknown files (miss on all tables)

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use scanner_git::path_policy::{classify_path, ext_in_skip_set};

/// Realistic mix of paths a git scan would encounter.
const MIXED_PATHS: &[&[u8]] = &[
    // Source files
    b"src/main.rs",
    b"lib/utils.js",
    b"app/models/user.py",
    b"pkg/server/handler.go",
    b"src/components/Button.tsx",
    // Binary files
    b"assets/logo.png",
    b"build/app.exe",
    b"dist/bundle.wasm",
    b"fonts/roboto.woff2",
    b"media/video.mp4",
    // Lock files
    b"Cargo.lock",
    b"go.sum",
    b"Gemfile.lock",
    // Unknown / no-match
    b"README",
    b"Makefile",
    b"data/export.csv",
    b".env",
    b"Dockerfile",
    b"config/settings.toml",
    b"docs/api.md",
];

/// Extensions that should hit the skip set.
const BINARY_EXTS: &[&[u8]] = &[
    b"png", b"jpg", b"gif", b"zip", b"gz", b"exe", b"dll", b"wasm", b"mp4", b"pdf", b"woff2",
    b"ttf", b"rar", b"7z", b"iso", b"dmg",
];

/// Extensions that should NOT hit the skip set.
const SOURCE_EXTS: &[&[u8]] = &[
    b"rs", b"py", b"js", b"go", b"java", b"ts", b"rb", b"cpp", b"html", b"css", b"json", b"yaml",
    b"sql", b"md", b"txt", b"xml",
];

/// Classify a realistic mix of 20 paths (source, binary, lock, unknown).
fn bench_classify_path_mixed(c: &mut Criterion) {
    c.bench_function("path_policy/classify_path_mixed_20", |b| {
        b.iter(|| {
            for path in MIXED_PATHS {
                black_box(classify_path(black_box(path)));
            }
        });
    });
}

/// Probe 16 extensions that are all in the binary skip set (all-hit case).
fn bench_ext_in_skip_set_hit(c: &mut Criterion) {
    c.bench_function("path_policy/ext_in_skip_set_hit_16", |b| {
        b.iter(|| {
            for ext in BINARY_EXTS {
                black_box(ext_in_skip_set(black_box(ext)));
            }
        });
    });
}

/// Probe 16 source-code extensions that should all miss the skip set.
fn bench_ext_in_skip_set_miss(c: &mut Criterion) {
    c.bench_function("path_policy/ext_in_skip_set_miss_16", |b| {
        b.iter(|| {
            for ext in SOURCE_EXTS {
                black_box(ext_in_skip_set(black_box(ext)));
            }
        });
    });
}

/// Classify 8 source-only paths (best-case for the extension table).
fn bench_classify_path_source_only(c: &mut Criterion) {
    let source_paths: &[&[u8]] = &[
        b"src/main.rs",
        b"src/lib.rs",
        b"tests/integration.rs",
        b"src/engine/core.rs",
        b"src/api.rs",
        b"app/models/user.py",
        b"lib/index.js",
        b"cmd/server/main.go",
    ];
    c.bench_function("path_policy/classify_path_source_8", |b| {
        b.iter(|| {
            for path in source_paths {
                black_box(classify_path(black_box(path)));
            }
        });
    });
}

/// Classify 8 binary-only paths (worst-case: all hit the skip set).
fn bench_classify_path_binary_only(c: &mut Criterion) {
    let binary_paths: &[&[u8]] = &[
        b"assets/logo.png",
        b"build/app.exe",
        b"dist/bundle.wasm",
        b"fonts/roboto.woff2",
        b"media/video.mp4",
        b"archive/backup.tar.gz",
        b"images/hero.jpg",
        b"lib/native.so",
    ];
    c.bench_function("path_policy/classify_path_binary_8", |b| {
        b.iter(|| {
            for path in binary_paths {
                black_box(classify_path(black_box(path)));
            }
        });
    });
}

criterion_group!(
    benches,
    bench_classify_path_mixed,
    bench_ext_in_skip_set_hit,
    bench_ext_in_skip_set_miss,
    bench_classify_path_source_only,
    bench_classify_path_binary_only,
);
criterion_main!(benches);
