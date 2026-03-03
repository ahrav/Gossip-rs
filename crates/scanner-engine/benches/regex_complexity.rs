//! Benchmark to test the hypothesis: complex regexes are the throughput bottleneck.
//!
//! This benchmark compares:
//! 1. Simple rules with literal patterns (e.g., `AKIA[A-Z0-9]{16}`)
//! 2. Complex rules with gitleaks-style patterns (optional prefixes, alternations, etc.)
//! 3. Two-stage approach: literal search -> windowed regex
//!
//! Run with: cargo bench --bench regex_complexity

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use regex::bytes::Regex;

fn build_regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("invalid regex pattern")
}

/// Generate test data with some anchor hits
fn generate_test_data(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    // Fill with realistic-ish ASCII
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = match i % 100 {
            0..=69 => b'a' + (i % 26) as u8,  // lowercase letters
            70..=79 => b'0' + (i % 10) as u8, // digits
            80..=89 => b' ',                  // spaces
            90..=94 => b'\n',                 // newlines
            _ => b'_',                        // underscores
        };
    }

    // Inject some anchors that will hit but not match full regex
    let anchors = [
        b"AKIA".as_slice(),
        b"ghp_".as_slice(),
        b"xoxb-".as_slice(),
        b"sk_live_".as_slice(),
        b"eyJ".as_slice(),
        b"AIza".as_slice(),
        b"npm_".as_slice(),
        b"SG.".as_slice(),
    ];

    // Inject anchors every ~100KB to create anchor hits
    for (i, anchor) in anchors.iter().cycle().enumerate() {
        let pos = i * 100_000;
        if pos + anchor.len() >= size {
            break;
        }
        data[pos..pos + anchor.len()].copy_from_slice(anchor);
    }

    data
}

/// Benchmark regex-only cost: simple vs complex patterns
fn benchmark_regex_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("regex_only");

    let size = 4 * 1024 * 1024;
    let data = generate_test_data(size);
    group.throughput(Throughput::Bytes(size as u64));

    // Simple regexes: literal prefix + fixed character class
    let simple_regexes: Vec<Regex> = vec![
        build_regex(r"AKIA[A-Z0-9]{16}"),
        build_regex(r"ghp_[A-Za-z0-9]{36}"),
        build_regex(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        build_regex(r"sk_live_[a-zA-Z0-9]{24,34}"),
        build_regex(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
        build_regex(r"AIza[A-Za-z0-9_-]{35}"),
        build_regex(r"npm_[A-Za-z0-9]{36}"),
        build_regex(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        build_regex(r"pypi-[A-Za-z0-9_-]{50,}"),
        build_regex(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    ];

    // Complex regexes: gitleaks-style with optional prefixes, case-insensitive, alternations
    let complex_regexes: Vec<Regex> = vec![
        build_regex(
            r#"(?i)[\w.-]{0,50}?(?:aws|amazon)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
        build_regex(
            r#"(?i)[\w.-]{0,50}?(?:github|gh)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(ghp_[A-Za-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
        build_regex(
            r#"(?i)[\w.-]{0,50}?(?:slack)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
        build_regex(
            r#"(?i)[\w.-]{0,50}?(?:stripe)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{24,99})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
        build_regex(
            r#"\b(eyJ[a-zA-Z0-9]{16,}\.eyJ[a-zA-Z0-9\/\\_-]{16,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
        build_regex(
            r#"(?i)[\w.-]{0,50}?(?:google|gcp|firebase)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(AIza[\w-]{35})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
        build_regex(
            r#"(?i)[\w.-]{0,50}?(?:npm)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(npm_[A-Za-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
        build_regex(
            r#"(?i)[\w.-]{0,50}?(?:sendgrid)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
        build_regex(
            r#"(?i)[\w.-]{0,50}?(?:pypi)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(pypi-[A-Za-z0-9_-]{50,})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
        build_regex(r"-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----"),
    ];

    group.bench_function("10_simple_regex_full_scan", |b| {
        b.iter(|| {
            let mut count = 0;
            for re in &simple_regexes {
                count += re.find_iter(black_box(&data)).count();
            }
            black_box(count)
        });
    });

    group.bench_function("10_complex_regex_full_scan", |b| {
        b.iter(|| {
            let mut count = 0;
            for re in &complex_regexes {
                count += re.find_iter(black_box(&data)).count();
            }
            black_box(count)
        });
    });

    group.finish();
}

/// Benchmark simulating two-stage approach:
/// Stage 1: Fast literal search (memchr)
/// Stage 2: Full regex only on windows around hits
fn benchmark_two_stage(c: &mut Criterion) {
    use memchr::memmem;

    let mut group = c.benchmark_group("two_stage_approach");

    let size = 4 * 1024 * 1024;
    let data = generate_test_data(size);
    group.throughput(Throughput::Bytes(size as u64));

    let anchor = b"AKIA";
    let simple_re = build_regex(r"AKIA[A-Z0-9]{16}");
    let complex_re = build_regex(
        r#"(?i)[\w.-]{0,50}?(?:aws|amazon)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)"#,
    );

    let finder = memmem::Finder::new(anchor);

    group.bench_function("1_literal_search_only", |b| {
        b.iter(|| {
            let mut count = 0;
            let mut pos = 0;
            while let Some(offset) = finder.find(&data[pos..]) {
                count += 1;
                pos += offset + 1;
            }
            black_box(count)
        });
    });

    group.bench_function("2_literal_then_simple_regex", |b| {
        b.iter(|| {
            let mut matches = 0;
            let mut pos = 0;
            while let Some(offset) = finder.find(&data[pos..]) {
                let abs_pos = pos + offset;
                let start = abs_pos.saturating_sub(64);
                let end = (abs_pos + 64).min(data.len());
                let window = &data[start..end];

                if simple_re.is_match(window) {
                    matches += 1;
                }
                pos = abs_pos + 1;
            }
            black_box(matches)
        });
    });

    group.bench_function("3_literal_then_complex_regex", |b| {
        b.iter(|| {
            let mut matches = 0;
            let mut pos = 0;
            while let Some(offset) = finder.find(&data[pos..]) {
                let abs_pos = pos + offset;
                let start = abs_pos.saturating_sub(256);
                let end = (abs_pos + 256).min(data.len());
                let window = &data[start..end];

                if complex_re.is_match(window) {
                    matches += 1;
                }
                pos = abs_pos + 1;
            }
            black_box(matches)
        });
    });

    group.bench_function("4_literal_then_simple_then_complex", |b| {
        b.iter(|| {
            let mut matches = 0;
            let mut pos = 0;
            while let Some(offset) = finder.find(&data[pos..]) {
                let abs_pos = pos + offset;
                let start = abs_pos.saturating_sub(64);
                let end = (abs_pos + 256).min(data.len());
                let window = &data[start..end];

                if simple_re.is_match(window) && complex_re.is_match(window) {
                    matches += 1;
                }
                pos = abs_pos + 1;
            }
            black_box(matches)
        });
    });

    group.finish();
}

/// Compare full-buffer regex scan vs windowed scan with many anchor hits
fn benchmark_anchor_hit_rate(c: &mut Criterion) {
    use memchr::memmem;

    let mut group = c.benchmark_group("anchor_hit_rate");

    let size = 4 * 1024 * 1024;

    let mut dense_data = generate_test_data(size);
    let anchor = b"AKIA";
    for i in 0..(size / 1024) {
        let pos = i * 1024;
        if pos + anchor.len() < size {
            dense_data[pos..pos + anchor.len()].copy_from_slice(anchor);
        }
    }

    group.throughput(Throughput::Bytes(size as u64));

    let simple_re = build_regex(r"AKIA[A-Z0-9]{16}");
    let complex_re = build_regex(
        r#"(?i)[\w.-]{0,50}?(?:aws|amazon)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)"#,
    );
    let finder = memmem::Finder::new(anchor);

    let hit_count = {
        let mut count = 0;
        let mut pos = 0;
        while let Some(offset) = finder.find(&dense_data[pos..]) {
            count += 1;
            pos += offset + 1;
        }
        count
    };

    group.bench_function(format!("dense_{}_hits_simple_full_scan", hit_count), |b| {
        b.iter(|| black_box(simple_re.find_iter(black_box(&dense_data)).count()));
    });

    group.bench_function(format!("dense_{}_hits_complex_full_scan", hit_count), |b| {
        b.iter(|| black_box(complex_re.find_iter(black_box(&dense_data)).count()));
    });

    group.bench_function(format!("dense_{}_hits_windowed_simple", hit_count), |b| {
        b.iter(|| {
            let mut matches = 0;
            let mut pos = 0;
            while let Some(offset) = finder.find(&dense_data[pos..]) {
                let abs_pos = pos + offset;
                let start = abs_pos.saturating_sub(64);
                let end = (abs_pos + 64).min(dense_data.len());
                let window = &dense_data[start..end];

                if simple_re.is_match(window) {
                    matches += 1;
                }
                pos = abs_pos + 1;
            }
            black_box(matches)
        });
    });

    group.bench_function(format!("dense_{}_hits_windowed_complex", hit_count), |b| {
        b.iter(|| {
            let mut matches = 0;
            let mut pos = 0;
            while let Some(offset) = finder.find(&dense_data[pos..]) {
                let abs_pos = pos + offset;
                let start = abs_pos.saturating_sub(256);
                let end = (abs_pos + 256).min(dense_data.len());
                let window = &dense_data[start..end];

                if complex_re.is_match(window) {
                    matches += 1;
                }
                pos = abs_pos + 1;
            }
            black_box(matches)
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_regex_only,
    benchmark_two_stage,
    benchmark_anchor_hit_rate,
);
criterion_main!(benches);
