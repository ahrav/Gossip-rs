use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use scanner_engine::{DelimAfter, TailCharset};

#[inline(always)]
/// Bench helper: ASCII word-byte classifier for boundary checks.
fn bench_is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[inline(always)]
/// Bench helper: tests whether a byte belongs to a validator tail charset.
fn bench_tail_matches_charset(byte: u8, charset: TailCharset) -> bool {
    match charset {
        TailCharset::UpperAlnum => matches!(byte, b'A'..=b'Z' | b'0'..=b'9'),
        TailCharset::Alnum => byte.is_ascii_alphanumeric(),
        TailCharset::LowerAlnum => matches!(byte, b'a'..=b'z' | b'0'..=b'9'),
        TailCharset::AlnumDashUnderscore => {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
        }
        TailCharset::Sendgrid66Set => {
            byte.is_ascii_alphanumeric() || matches!(byte, b'=' | b'_' | b'-' | b'.')
        }
        TailCharset::DatabricksSet => matches!(byte, b'0'..=b'9' | b'a'..=b'h' | b'A'..=b'H'),
        TailCharset::Base64Std => byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/',
    }
}

#[inline(always)]
fn gitleaks_terminator(byte: u8) -> bool {
    byte == b'\'' || byte == b'"' || byte == b'`' || byte.is_ascii_whitespace()
}

#[inline(always)]
/// Bench helper: delimiter check for token validators.
fn delim_ok(buf: &[u8], pos: usize, delim_after: DelimAfter) -> bool {
    match delim_after {
        DelimAfter::None => true,
        DelimAfter::GitleaksTokenTerminator => {
            if pos >= buf.len() {
                return true;
            }
            gitleaks_terminator(buf[pos])
        }
    }
}

/// Bench helper: validates a fixed-length tail after a known prefix range.
fn bench_validate_prefix_fixed(
    buf: &[u8],
    start: usize,
    end: usize,
    tail_len: usize,
    tail: TailCharset,
    require_word_boundary: bool,
    delim_after: DelimAfter,
) -> bool {
    if end < start || end > buf.len() {
        return false;
    }
    if require_word_boundary && start > 0 && bench_is_word_byte(buf[start - 1]) {
        return false;
    }

    let tail_end = match end.checked_add(tail_len) {
        Some(pos) => pos,
        None => return false,
    };
    if tail_end > buf.len() {
        return false;
    }

    for &b in &buf[end..tail_end] {
        if !bench_tail_matches_charset(b, tail) {
            return false;
        }
    }

    delim_ok(buf, tail_end, delim_after)
}

#[allow(clippy::too_many_arguments)]
/// Bench helper: validates a bounded tail length after a known prefix range.
fn bench_validate_prefix_bounded(
    buf: &[u8],
    start: usize,
    end: usize,
    min_tail: usize,
    max_tail: usize,
    tail: TailCharset,
    require_word_boundary: bool,
    delim_after: DelimAfter,
) -> bool {
    if end < start || end > buf.len() || min_tail > max_tail {
        return false;
    }
    if require_word_boundary && start > 0 && bench_is_word_byte(buf[start - 1]) {
        return false;
    }

    let min_end = match end.checked_add(min_tail) {
        Some(pos) => pos,
        None => return false,
    };
    if min_end > buf.len() {
        return false;
    }

    let max_end = match end.checked_add(max_tail) {
        Some(pos) => pos.min(buf.len()),
        None => buf.len(),
    };

    let mut pos = end;
    while pos < max_end {
        let b = buf[pos];
        if !bench_tail_matches_charset(b, tail) {
            break;
        }
        pos += 1;
    }

    if pos < min_end {
        return false;
    }

    if delim_after == DelimAfter::None {
        return true;
    }

    delim_ok(buf, pos, delim_after)
}

/// Bench helper: validates an AWS access key token (20 bytes, uppercase/digits).
fn bench_validate_aws_access_key(buf: &[u8], start: usize, _end: usize) -> bool {
    const AWS_KEY_LEN: usize = 20;
    if start >= buf.len() {
        return false;
    }
    let end = match start.checked_add(AWS_KEY_LEN) {
        Some(pos) => pos,
        None => return false,
    };
    if end > buf.len() {
        return false;
    }
    buf[start..end]
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

// -----------------------------------------------------------------------------
// is_word_byte benchmarks
// -----------------------------------------------------------------------------

fn bench_is_word_byte_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_word_byte");

    group.bench_function("all_256_bytes", |b| {
        b.iter(|| {
            let mut count = 0u32;
            for byte in 0u8..=255 {
                if bench_is_word_byte(black_box(byte)) {
                    count += 1;
                }
            }
            black_box(count)
        })
    });

    // Focused benchmarks for common byte ranges
    group.bench_function("ascii_letters", |b| {
        b.iter(|| {
            let mut count = 0u32;
            for byte in b'A'..=b'Z' {
                if bench_is_word_byte(black_box(byte)) {
                    count += 1;
                }
            }
            for byte in b'a'..=b'z' {
                if bench_is_word_byte(black_box(byte)) {
                    count += 1;
                }
            }
            black_box(count)
        })
    });

    group.bench_function("digits", |b| {
        b.iter(|| {
            let mut count = 0u32;
            for byte in b'0'..=b'9' {
                if bench_is_word_byte(black_box(byte)) {
                    count += 1;
                }
            }
            black_box(count)
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// tail_matches_charset benchmarks
// -----------------------------------------------------------------------------

fn bench_tail_charset(c: &mut Criterion) {
    let charsets = [
        ("UpperAlnum", TailCharset::UpperAlnum),
        ("Alnum", TailCharset::Alnum),
        ("LowerAlnum", TailCharset::LowerAlnum),
        ("AlnumDashUnderscore", TailCharset::AlnumDashUnderscore),
        ("Sendgrid66Set", TailCharset::Sendgrid66Set),
        ("DatabricksSet", TailCharset::DatabricksSet),
        ("Base64Std", TailCharset::Base64Std),
    ];

    let mut group = c.benchmark_group("tail_matches_charset");

    for (name, charset) in charsets {
        group.bench_with_input(BenchmarkId::new("all_256", name), &charset, |b, &cs| {
            b.iter(|| {
                let mut count = 0u32;
                for byte in 0u8..=255 {
                    if bench_tail_matches_charset(black_box(byte), cs) {
                        count += 1;
                    }
                }
                black_box(count)
            })
        });
    }

    group.finish();
}

// -----------------------------------------------------------------------------
// validate_prefix_fixed benchmarks
// -----------------------------------------------------------------------------

fn make_valid_token(prefix: &[u8], tail_len: usize) -> Vec<u8> {
    let mut buf = prefix.to_vec();
    // Alphanumeric tail
    for i in 0..tail_len {
        buf.push(b'A' + (i as u8 % 26));
    }
    buf
}

fn bench_validate_fixed(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_prefix_fixed");

    // Successful match
    let valid_buf = make_valid_token(b"ghp_", 40);
    group.bench_function("success", |b| {
        b.iter(|| {
            bench_validate_prefix_fixed(
                black_box(&valid_buf),
                0,
                4,
                40,
                TailCharset::AlnumDashUnderscore,
                false,
                DelimAfter::None,
            )
        })
    });

    // Early fail (invalid char at position 5)
    let mut early_fail = make_valid_token(b"ghp_", 40);
    early_fail[5] = b'@';
    group.bench_function("early_fail", |b| {
        b.iter(|| {
            bench_validate_prefix_fixed(
                black_box(&early_fail),
                0,
                4,
                40,
                TailCharset::AlnumDashUnderscore,
                false,
                DelimAfter::None,
            )
        })
    });

    // Word boundary check failure
    let mut no_boundary = make_valid_token(b"aghp_", 40);
    no_boundary.insert(0, b'a'); // prepend 'a' so no boundary at position 1
    group.bench_function("boundary_fail", |b| {
        let buf = make_valid_token(b"aghp_", 40);
        b.iter(|| {
            bench_validate_prefix_fixed(
                black_box(&buf),
                1,
                5,
                40,
                TailCharset::AlnumDashUnderscore,
                true, // require word boundary
                DelimAfter::None,
            )
        })
    });

    // With gitleaks terminator
    let mut with_term = make_valid_token(b"token_", 20);
    with_term.push(b'\'');
    group.bench_function("with_terminator", |b| {
        b.iter(|| {
            bench_validate_prefix_fixed(
                black_box(&with_term),
                0,
                6,
                20,
                TailCharset::Alnum,
                false,
                DelimAfter::GitleaksTokenTerminator,
            )
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// validate_prefix_bounded benchmarks
// -----------------------------------------------------------------------------

fn bench_validate_bounded(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_prefix_bounded");

    // No backtracking needed (greedy match, no delimiter)
    let buf = make_valid_token(b"xoxb-", 30);
    group.bench_function("no_backtrack", |b| {
        b.iter(|| {
            bench_validate_prefix_bounded(
                black_box(&buf),
                0,
                5,
                10,
                40,
                TailCharset::AlnumDashUnderscore,
                false,
                DelimAfter::None,
            )
        })
    });

    // Short backtrack (terminator after a few chars)
    let mut short_bt = make_valid_token(b"token_", 10);
    short_bt.push(b'\'');
    short_bt.extend_from_slice(b"more");
    group.bench_function("short_backtrack", |b| {
        b.iter(|| {
            bench_validate_prefix_bounded(
                black_box(&short_bt),
                0,
                6,
                5,
                40,
                TailCharset::Alnum,
                false,
                DelimAfter::GitleaksTokenTerminator,
            )
        })
    });

    // Long backtrack (terminator only at minimum)
    let mut long_bt = make_valid_token(b"token_", 30);
    // Insert terminator at min position
    long_bt[6 + 5] = b'\''; // position 11 (after 5 tail chars)
    // But the chars after are not in charset, so we'll backtrack
    for b in long_bt.iter_mut().skip(12) {
        *b = b'@'; // non-matching
    }
    // Actually, let's make a proper long backtrack scenario
    let mut long_bt = b"token_".to_vec();
    for i in 0..30 {
        long_bt.push(b'A' + (i as u8 % 26));
    }
    long_bt.push(b'@'); // non-terminator, forces full scan
    group.bench_function("long_backtrack", |b| {
        b.iter(|| {
            bench_validate_prefix_bounded(
                black_box(&long_bt),
                0,
                6,
                5,
                30,
                TailCharset::Alnum,
                false,
                DelimAfter::GitleaksTokenTerminator, // will fail, need to backtrack
            )
        })
    });

    // Successful with terminator at various positions
    let mut varied = b"prefix".to_vec();
    for i in 0..25 {
        varied.push(b'0' + (i as u8 % 10));
    }
    varied.push(b'"'); // terminator
    group.bench_function("terminator_at_end", |b| {
        b.iter(|| {
            bench_validate_prefix_bounded(
                black_box(&varied),
                0,
                6,
                10,
                30,
                TailCharset::Alnum,
                false,
                DelimAfter::GitleaksTokenTerminator,
            )
        })
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// validate_aws_access_key benchmarks
// -----------------------------------------------------------------------------

fn bench_aws_access_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("validate_aws_access_key");

    // Valid 4-byte prefix (AKIA)
    let valid_4 = b"AKIAIOSFODNN7EXAMPLE";
    group.bench_function("valid_4byte", |b| {
        b.iter(|| bench_validate_aws_access_key(black_box(valid_4), 0, 4))
    });

    // Valid 3-byte prefix (A3T)
    let valid_3 = b"A3TABCDEFGHIJ1234567";
    group.bench_function("valid_3byte", |b| {
        b.iter(|| bench_validate_aws_access_key(black_box(valid_3), 0, 3))
    });

    // Invalid (lowercase)
    let invalid_lower = b"AKIAiosfodnn7example";
    group.bench_function("invalid_lowercase", |b| {
        b.iter(|| bench_validate_aws_access_key(black_box(invalid_lower), 0, 4))
    });

    // Invalid (too short)
    let invalid_short = b"AKIAIOSFODNN7EXAM";
    group.bench_function("invalid_short", |b| {
        b.iter(|| bench_validate_aws_access_key(black_box(invalid_short), 0, 4))
    });

    // With offset in larger buffer
    let with_offset = b"some text AKIAIOSFODNN7EXAMPLE more text";
    group.bench_function("with_offset", |b| {
        b.iter(|| bench_validate_aws_access_key(black_box(with_offset), 10, 14))
    });

    group.finish();
}

// -----------------------------------------------------------------------------
// Bulk validation benchmarks (simulating hot path)
// -----------------------------------------------------------------------------

fn bench_bulk_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulk_validation");

    // Simulate scanning many tokens in a buffer
    let mut bulk_buf = Vec::with_capacity(100_000);
    let mut positions = Vec::new();

    // Insert tokens at regular intervals
    let token_prefix = b"ghp_";
    let token_tail: &[u8] = b"1234567890123456789012345678901234567890";
    let spacing = 100;

    let mut pos = 0usize;
    while pos + token_prefix.len() + token_tail.len() < 100_000 {
        // Fill with random-ish non-matching bytes
        while bulk_buf.len() < pos {
            bulk_buf.push(b'.');
        }
        positions.push((bulk_buf.len(), bulk_buf.len() + token_prefix.len()));
        bulk_buf.extend_from_slice(token_prefix);
        bulk_buf.extend_from_slice(token_tail);
        pos = bulk_buf.len() + spacing;
    }
    // Fill remaining
    while bulk_buf.len() < 100_000 {
        bulk_buf.push(b'.');
    }

    group.bench_function("1000_tokens_fixed", |b| {
        b.iter(|| {
            let mut matches = 0u32;
            for &(start, end) in &positions {
                if bench_validate_prefix_fixed(
                    black_box(&bulk_buf),
                    start,
                    end,
                    40,
                    TailCharset::AlnumDashUnderscore,
                    false,
                    DelimAfter::None,
                ) {
                    matches += 1;
                }
            }
            black_box(matches)
        })
    });

    group.bench_function("1000_tokens_bounded", |b| {
        b.iter(|| {
            let mut matches = 0u32;
            for &(start, end) in &positions {
                if bench_validate_prefix_bounded(
                    black_box(&bulk_buf),
                    start,
                    end,
                    30,
                    50,
                    TailCharset::AlnumDashUnderscore,
                    false,
                    DelimAfter::None,
                ) {
                    matches += 1;
                }
            }
            black_box(matches)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_is_word_byte_all,
    bench_tail_charset,
    bench_validate_fixed,
    bench_validate_bounded,
    bench_aws_access_key,
    bench_bulk_validation
);
criterion_main!(benches);
