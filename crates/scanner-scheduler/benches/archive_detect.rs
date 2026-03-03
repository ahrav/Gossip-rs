//! Benchmarks for `detect_kind_from_name_bytes`.
//!
//! Three groups:
//! - `no_match_batch` — 10 typical non-matching filenames (common case)
//! - `match_by_extension` — one benchmark per recognized extension
//! - `realistic_1000` — 1000 entries with ~5% archive names

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use scanner_scheduler::archive::detect::detect_kind_from_name_bytes;

/// Typical non-matching filenames found inside tar archives.
const NO_MATCH: &[&[u8]] = &[
    b"src/main.rs",
    b"package.json",
    b"README.md",
    b"lib/utils.js",
    b"Makefile",
    b"config/settings.yaml",
    b"docs/api.html",
    b"tests/test_core.py",
    b"data/schema.sql",
    b"assets/logo.png",
];

fn bench_no_match_batch(c: &mut Criterion) {
    c.bench_function("detect/no_match_batch_10", |b| {
        b.iter(|| {
            for name in NO_MATCH {
                black_box(detect_kind_from_name_bytes(black_box(name)));
            }
        });
    });
}

fn bench_match_by_extension(c: &mut Criterion) {
    let cases: &[(&str, &[u8])] = &[
        ("tar.gz", b"archive.tar.gz" as &[u8]),
        ("TAR.GZ", b"archive.TAR.GZ"),
        ("tgz", b"archive.tgz"),
        ("TGZ", b"archive.TGZ"),
        ("tar", b"data.tar"),
        ("TAR", b"data.TAR"),
        ("gz", b"file.gz"),
        ("GZ", b"file.GZ"),
        ("zip", b"bundle.zip"),
        ("ZIP", b"bundle.ZIP"),
        ("tar.gz/", b"archive.tar.gz/"),
        ("zip\\", b"bundle.zip\\"),
    ];

    let mut group = c.benchmark_group("detect/match_by_ext");
    for (label, input) in cases {
        group.bench_function(*label, |b| {
            b.iter(|| black_box(detect_kind_from_name_bytes(black_box(*input))));
        });
    }
    group.finish();
}

/// Build a realistic 1000-entry workload: ~5% archives, 95% regular files.
fn build_realistic_names() -> Vec<Vec<u8>> {
    let regular: &[&[u8]] = &[
        b"src/main.rs",
        b"src/lib.rs",
        b"package.json",
        b"README.md",
        b"Cargo.toml",
        b"Makefile",
        b"config.yaml",
        b"data.csv",
        b"index.html",
        b"style.css",
        b"app.js",
        b"utils.py",
        b"schema.sql",
        b"Dockerfile",
        b"LICENSE",
        b"test_core.py",
        b"module.ts",
        b"image.png",
        b"font.woff2",
    ];
    let archives: &[&[u8]] = &[
        b"vendor.tar.gz",
        b"deps.tgz",
        b"backup.tar",
        b"data.gz",
        b"release.zip",
        b"nested/lib.TAR.GZ",
        b"cache/old.TGZ",
        b"mirror/src.ZIP",
    ];

    let mut names = Vec::with_capacity(1000);
    // ~5% archives (50 out of 1000)
    for i in 0..1000u32 {
        if i % 20 == 0 {
            // Every 20th entry is an archive
            names.push(archives[(i as usize / 20) % archives.len()].to_vec());
        } else {
            names.push(regular[i as usize % regular.len()].to_vec());
        }
    }
    names
}

fn bench_realistic_1000(c: &mut Criterion) {
    let names = build_realistic_names();
    c.bench_function("detect/realistic_1000", |b| {
        b.iter(|| {
            for name in &names {
                black_box(detect_kind_from_name_bytes(black_box(name)));
            }
        });
    });
}

criterion_group!(
    benches,
    bench_no_match_batch,
    bench_match_by_extension,
    bench_realistic_1000,
);
criterion_main!(benches);
