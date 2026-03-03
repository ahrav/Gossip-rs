//! Scanner Throughput Benchmarks
//!
//! This benchmark suite measures end-to-end scanner throughput across different
//! workload tiers to establish practical performance targets and identify bottlenecks.
//!
//! # Throughput Tiers
//!
//! | Tier | Description | Expected Range |
//! |------|-------------|----------------|
//! | 1 | Vectorscan ceiling (no hits) | 40-80 GB/s |
//! | 2 | Prefilter hits, fast reject | 10-30 GB/s |
//! | 3 | Full validation path | 2-10 GB/s |
//! | 4 | Transform-heavy (Base64/URL) | 0.5-4 GB/s |
//!
//! # Workload Categories
//!
//! - **Random bytes**: Baseline with no pattern matches
//! - **ASCII text**: Realistic text without secrets
//! - **Sparse hits**: Occasional anchor matches, no regex match
//! - **Dense hits**: Many anchor matches, some regex matches
//! - **Base64 heavy**: Lots of base64-encoded content
//! - **URL encoded**: URL percent-encoded payloads
//! - **Mixed realistic**: Simulated real-world distribution
//!
//! # Running
//!
//! ```bash
//! # All throughput benchmarks
//! cargo bench --bench scanner_throughput
//!
//! # Specific tier
//! cargo bench --bench scanner_throughput -- tier1
//! cargo bench --bench scanner_throughput -- tier2
//! cargo bench --bench scanner_throughput -- tier3
//! cargo bench --bench scanner_throughput -- tier4
//!
//! # Specific workload
//! cargo bench --bench scanner_throughput -- random
//! cargo bench --bench scanner_throughput -- base64
//! ```

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STD;
use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, black_box, criterion_group, criterion_main,
};
use scanner_engine::{
    AnchorMode, AnchorPolicy, Engine, RuleSpec, Tuning, demo_engine_with_anchor_mode, demo_tuning,
};

// ============================================================================
// Configuration
// ============================================================================

/// Buffer sizes for throughput measurement.
/// Larger buffers amortize per-call overhead and reveal steady-state throughput.
const BUFFER_SIZES: &[(usize, &str)] = &[
    (64 * 1024, "64KB"),
    (256 * 1024, "256KB"),
    (1024 * 1024, "1MB"),
    (4 * 1024 * 1024, "4MB"),
    (16 * 1024 * 1024, "16MB"),
];

/// Primary buffer size for comparative benchmarks.
const PRIMARY_SIZE: usize = 4 * 1024 * 1024;

// ============================================================================
// PRNG for Reproducible Data Generation
// ============================================================================

/// Fast xorshift64 PRNG for reproducible benchmark data.
///
/// # Why xorshift64?
///
/// We need reproducible pseudo-random data for benchmarking. The choice of xorshift64
/// over alternatives reflects specific benchmark requirements:
///
/// - **Speed**: xorshift64 is ~3-5x faster than ChaCha or Mersenne Twister. Since we
///   generate multi-megabyte buffers, PRNG overhead must be negligible compared to
///   the scanner operations we're measuring.
///
/// - **Reproducibility**: Same seed produces identical byte sequences across runs,
///   enabling meaningful performance comparisons over time.
///
/// - **Statistical quality**: For benchmark data generation (not cryptography), xorshift64
///   provides sufficient uniformity. We're simulating file content, not generating keys.
///
/// - **Simplicity**: No external dependencies, trivial to inline, and the algorithm fits
///   in a few lines. This matters for benchmark clarity.
///
/// The 64-bit variant specifically allows us to fill 8 bytes per iteration, which is
/// important when generating megabyte-scale buffers efficiently.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0xDEAD_BEEF_CAFE_BABE
            } else {
                seed
            },
        }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }

    fn next_usize(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % max.max(1)
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= buf.len() {
            let v = self.next_u64().to_le_bytes();
            buf[i..i + 8].copy_from_slice(&v);
            i += 8;
        }
        while i < buf.len() {
            buf[i] = self.next_u8();
            i += 1;
        }
    }

    /// Fill with printable ASCII (0x20-0x7E).
    fn fill_printable_ascii(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = 0x20 + (self.next_u8() % 95);
        }
    }

    /// Fill with lowercase letters only.
    fn fill_lowercase(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = b'a' + (self.next_u8() % 26);
        }
    }

    /// Fill with valid base64 alphabet characters.
    fn fill_base64_alphabet(&mut self, buf: &mut [u8]) {
        const B64_CHARS: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for b in buf.iter_mut() {
            *b = B64_CHARS[(self.next_u8() & 0x3F) as usize];
        }
    }
}

// ============================================================================
// Workload Generators
// ============================================================================

/// Workload descriptor for benchmarking.
///
/// Each workload simulates a different class of real-world input that the scanner
/// might encounter. The combination of workloads covers the spectrum from best-case
/// (random bytes, no pattern matches) to worst-case (dense transform-encoded secrets).
///
/// # Design principle
///
/// Workloads are parameterized by "hit interval" - the approximate distance between
/// injected patterns. This allows measuring how throughput degrades as pattern density
/// increases, revealing the cost model of the scanner's post-filter validation path.
struct Workload {
    name: &'static str,
    data: Vec<u8>,
}

/// Generate random bytes - baseline, should trigger no patterns.
///
/// Random bytes establish the theoretical throughput ceiling. Since the byte
/// distribution is uniform, anchors like "AKIA" or "ghp_" have near-zero
/// probability of appearing, meaning Vectorscan runs without triggering callbacks.
fn gen_random_bytes(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut buf = vec![0u8; size];
    rng.fill_bytes(&mut buf);
    buf
}

/// Generate ASCII text without any secret-like patterns.
///
/// Unlike random bytes, ASCII text is representative of actual file content
/// (source code, config files, logs). Uses only lowercase letters to avoid
/// accidentally matching anchors like "AKIA" or "Bearer".
///
/// Newlines every ~80 chars simulate realistic line structure, which may
/// affect cache behavior and branch prediction in the scanner.
fn gen_clean_ascii(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut buf = vec![0u8; size];
    rng.fill_lowercase(&mut buf);

    // Add newlines every ~80 chars for realism
    for i in (80..buf.len()).step_by(80) {
        buf[i] = b'\n';
    }
    buf
}

/// Generate data with sparse anchor hits that won't match full regex.
///
/// This workload measures the "prefilter reject" path - the cost of triggering
/// Vectorscan's automaton without ultimately finding a valid secret.
///
/// # Why this matters
///
/// In real codebases, strings like "password", "secret", or partial token prefixes
/// appear frequently without being actual secrets. The scanner must handle these
/// efficiently - triggering the callback but quickly rejecting via regex or
/// surrounding-context checks.
///
/// The `hit_interval` parameter controls pattern density. Smaller intervals mean
/// more prefilter hits per megabyte, stressing the callback and regex validation
/// paths more heavily.
fn gen_sparse_anchor_hits(size: usize, seed: u64, hit_interval: usize) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut buf = vec![0u8; size];
    rng.fill_lowercase(&mut buf);

    // Anchors that exist in real rules but with surrounding context that won't match
    let fake_anchors: &[&[u8]] = &[
        b"AKIA",     // AWS key prefix, but not followed by valid chars
        b"ghp_",     // GitHub token prefix
        b"xoxb-",    // Slack token prefix
        b"sk_live_", // Stripe key prefix
        b"glpat-",   // GitLab token prefix
        b"Bearer ",  // Auth header
        b"api_key",  // Generic keyword
        b"password", // Generic keyword
        b"secret",   // Generic keyword
    ];

    let mut pos = hit_interval;
    let mut anchor_idx = 0;
    while pos + 50 < size {
        let anchor = fake_anchors[anchor_idx % fake_anchors.len()];
        if pos + anchor.len() < size {
            buf[pos..pos + anchor.len()].copy_from_slice(anchor);
            // Follow with lowercase to ensure regex doesn't match
            for i in 0..20.min(size - pos - anchor.len()) {
                buf[pos + anchor.len() + i] = b'x';
            }
        }
        pos += hit_interval;
        anchor_idx += 1;
    }

    buf
}

/// Generate data with real-looking but fake AWS keys.
///
/// These patterns match the full validation path: anchor hit → regex match →
/// validator check. AWS Access Key IDs follow the format `AKIA[A-Z0-9]{16}`,
/// which we replicate with random uppercase alphanumeric suffixes.
///
/// The keys are "fake" in that they were never issued by AWS, but they're
/// structurally valid, meaning the scanner must run the complete detection
/// pipeline. This measures Tier 3 (full validation) throughput.
fn gen_aws_key_hits(size: usize, seed: u64, hit_interval: usize) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut buf = vec![0u8; size];
    rng.fill_lowercase(&mut buf);

    // Valid-looking AWS access key format: AKIA + 16 uppercase alphanumeric
    let mut pos = hit_interval;
    while pos + 30 < size {
        // Generate a fake but valid-format AWS key
        buf[pos..pos + 4].copy_from_slice(b"AKIA");
        for i in 0..16 {
            let c = match rng.next_u8() % 36 {
                0..=9 => b'0' + (rng.next_u8() % 10),
                _ => b'A' + (rng.next_u8() % 26),
            };
            buf[pos + 4 + i] = c;
        }
        pos += hit_interval;
    }

    buf
}

/// Generate data with GitHub token format matches.
fn gen_github_token_hits(size: usize, seed: u64, hit_interval: usize) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut buf = vec![0u8; size];
    rng.fill_lowercase(&mut buf);

    // ghp_ followed by 36 alphanumeric characters
    let mut pos = hit_interval;
    while pos + 50 < size {
        buf[pos..pos + 4].copy_from_slice(b"ghp_");
        for i in 0..36 {
            let c = match rng.next_u8() % 62 {
                0..=9 => b'0' + (rng.next_u8() % 10),
                10..=35 => b'a' + (rng.next_u8() % 26),
                _ => b'A' + (rng.next_u8() % 26),
            };
            buf[pos + 4 + i] = c;
        }
        pos += hit_interval;
    }

    buf
}

/// Generate base64-encoded content with embedded secrets.
///
/// This is the most expensive workload tier. The scanner must:
/// 1. Detect base64-like content (alphabet check, length heuristics)
/// 2. Decode the content to a scratch buffer
/// 3. Re-scan the decoded content for secrets
/// 4. Potentially recurse if the decoded content is also encoded
///
/// The `secret_interval` controls how often a real encoded secret appears.
/// Between secrets, we fill with valid base64 alphabet characters that decode
/// to garbage, simulating the common case of base64-encoded binary data
/// (images, compiled assets) that doesn't contain secrets.
fn gen_base64_with_secrets(size: usize, seed: u64, secret_interval: usize) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut buf = Vec::with_capacity(size);

    // Fill with base64 content containing occasional encoded secrets
    let fake_aws = b"AKIAIOSFODNN7EXAMPLE";
    let encoded_secret = B64_STD.encode(fake_aws);

    while buf.len() < size {
        // Add a chunk of random base64
        let chunk_size = rng.next_usize(200) + 100;
        let remaining = size.saturating_sub(buf.len());
        let actual_chunk = chunk_size.min(remaining);

        if actual_chunk == 0 {
            break;
        }

        let mut chunk = vec![0u8; actual_chunk];
        rng.fill_base64_alphabet(&mut chunk);

        // Maybe inject an encoded secret
        if buf.len() % secret_interval < chunk_size && encoded_secret.len() < chunk.len() {
            let offset = rng.next_usize(chunk.len().saturating_sub(encoded_secret.len()));
            chunk[offset..offset + encoded_secret.len()].copy_from_slice(encoded_secret.as_bytes());
        }

        buf.extend_from_slice(&chunk);
        buf.push(b'\n');
    }

    buf.truncate(size);
    buf
}

/// Generate base64 content without any secrets (pure noise).
///
/// Tests the effectiveness of "gating" heuristics that avoid decoding base64
/// content unlikely to contain secrets. If gating works well, this workload
/// should approach Tier 2 throughput despite being all base64 alphabet.
///
/// Standard 76-character line length matches MIME base64 formatting.
fn gen_base64_noise(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut buf = Vec::with_capacity(size);

    while buf.len() < size {
        let line_len = 76; // Standard base64 line length
        let remaining = size.saturating_sub(buf.len());
        let actual_len = line_len.min(remaining.saturating_sub(1));

        if actual_len == 0 {
            break;
        }

        let mut line = vec![0u8; actual_len];
        rng.fill_base64_alphabet(&mut line);
        buf.extend_from_slice(&line);
        if buf.len() < size {
            buf.push(b'\n');
        }
    }

    buf.truncate(size);
    buf
}

/// Generate URL-encoded content.
///
/// URL encoding (`%XX` escapes) requires character-by-character scanning and
/// in-place or buffered decoding. The `escape_density` parameter controls
/// what fraction of characters are percent-encoded (0.0 = none, 1.0 = all).
///
/// Real-world URL encoding varies widely:
/// - Query strings: ~5-15% escape density (mostly alphanumeric)
/// - Binary in URLs: ~30%+ escape density
///
/// Unlike base64, URL decoding is typically O(n) in-place without expansion,
/// but the per-character decode logic has higher overhead than streaming base64.
fn gen_url_encoded(size: usize, seed: u64, escape_density: f32) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut buf = Vec::with_capacity(size);

    while buf.len() < size {
        let r = (rng.next_u8() as f32) / 255.0;
        if r < escape_density {
            // Emit a %XX escape
            let hex_val = rng.next_u8();
            buf.push(b'%');
            buf.push(b"0123456789ABCDEF"[(hex_val >> 4) as usize]);
            buf.push(b"0123456789ABCDEF"[(hex_val & 0x0F) as usize]);
        } else {
            // Emit a URL-safe character
            let c = match rng.next_u8() % 64 {
                0..=25 => b'a' + (rng.next_u8() % 26),
                26..=51 => b'A' + (rng.next_u8() % 26),
                52..=61 => b'0' + (rng.next_u8() % 10),
                62 => b'-',
                _ => b'_',
            };
            buf.push(c);
        }

        // Occasional query param separators
        if rng.next_u8() < 10 {
            buf.push(b'&');
        }
    }

    buf.truncate(size);
    buf
}

/// Generate mixed realistic content simulating a code repository.
///
/// Real repositories contain a heterogeneous mix of content types, each with
/// different scanning characteristics. This generator produces a weighted
/// distribution approximating typical codebase composition:
///
/// - **Code (41%)**: Rust-like keywords and identifiers
/// - **Config (20%)**: Key-value pairs mimicking TOML/env files
/// - **JSON (15%)**: Nested object structures
/// - **Base64 (10%)**: Encoded blobs (certificates, binary assets)
/// - **Plain text (14%)**: Documentation, comments, READMEs
///
/// The mix exercises all scanner paths in proportions that reflect reality,
/// making this the best single-number benchmark for "typical" performance.
fn gen_mixed_realistic(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut buf = Vec::with_capacity(size);

    // Content types with approximate frequencies
    enum ContentType {
        Code,
        Config,
        Base64Block,
        JsonBlob,
        PlainText,
    }

    while buf.len() < size {
        let content_type = match rng.next_u8() % 100 {
            0..=40 => ContentType::Code,
            41..=60 => ContentType::Config,
            61..=75 => ContentType::JsonBlob,
            76..=85 => ContentType::Base64Block,
            _ => ContentType::PlainText,
        };

        let chunk_size = match content_type {
            ContentType::Code => rng.next_usize(500) + 100,
            ContentType::Config => rng.next_usize(300) + 50,
            ContentType::Base64Block => rng.next_usize(200) + 50,
            ContentType::JsonBlob => rng.next_usize(400) + 100,
            ContentType::PlainText => rng.next_usize(200) + 50,
        };

        let remaining = size.saturating_sub(buf.len());
        let actual_size = chunk_size.min(remaining);
        if actual_size == 0 {
            break;
        }

        match content_type {
            ContentType::Code => {
                // Simulate code with keywords
                let keywords = [
                    "fn ", "let ", "const ", "if ", "for ", "return ", "struct ", "impl ",
                ];
                let mut chunk = Vec::with_capacity(actual_size);
                while chunk.len() < actual_size {
                    if rng.next_u8() < 30 {
                        let kw = keywords[rng.next_usize(keywords.len())];
                        chunk.extend_from_slice(kw.as_bytes());
                    } else {
                        chunk.push(b'a' + (rng.next_u8() % 26));
                    }
                    if rng.next_u8() < 20 {
                        chunk.push(b'\n');
                    }
                }
                chunk.truncate(actual_size);
                buf.extend_from_slice(&chunk);
            }
            ContentType::Config => {
                // Simulate config with key=value pairs
                let mut chunk = Vec::with_capacity(actual_size);
                while chunk.len() < actual_size {
                    // key
                    for _ in 0..rng.next_usize(10) + 3 {
                        chunk.push(b'a' + (rng.next_u8() % 26));
                    }
                    chunk.extend_from_slice(b"=\"");
                    // value
                    for _ in 0..rng.next_usize(20) + 5 {
                        chunk.push(b'a' + (rng.next_u8() % 26));
                    }
                    chunk.extend_from_slice(b"\"\n");
                }
                chunk.truncate(actual_size);
                buf.extend_from_slice(&chunk);
            }
            ContentType::Base64Block => {
                let mut chunk = vec![0u8; actual_size];
                rng.fill_base64_alphabet(&mut chunk);
                // Add line breaks
                for i in (76..chunk.len()).step_by(77) {
                    chunk[i] = b'\n';
                }
                buf.extend_from_slice(&chunk);
            }
            ContentType::JsonBlob => {
                let mut chunk = Vec::with_capacity(actual_size);
                chunk.extend_from_slice(b"{\"");
                while chunk.len() < actual_size.saturating_sub(3) {
                    // key
                    for _ in 0..rng.next_usize(8) + 2 {
                        chunk.push(b'a' + (rng.next_u8() % 26));
                    }
                    chunk.extend_from_slice(b"\":\"");
                    // value
                    for _ in 0..rng.next_usize(15) + 3 {
                        chunk.push(b'a' + (rng.next_u8() % 26));
                    }
                    chunk.extend_from_slice(b"\",\"");
                }
                chunk.truncate(actual_size.saturating_sub(2));
                chunk.extend_from_slice(b"\"}");
                buf.extend_from_slice(&chunk);
            }
            ContentType::PlainText => {
                let mut chunk = vec![0u8; actual_size];
                rng.fill_printable_ascii(&mut chunk);
                for i in (80..chunk.len()).step_by(81) {
                    chunk[i] = b'\n';
                }
                buf.extend_from_slice(&chunk);
            }
        }

        buf.push(b'\n');
    }

    buf.truncate(size);
    buf
}

// ============================================================================
// Engine Configurations
// ============================================================================

/// Create a minimal engine with a single simple rule for ceiling measurement.
///
/// This engine uses an "impossible" anchor pattern (`\xFF\xFE\xFD\xFC`) that
/// cannot appear in ASCII or typical file content. With zero anchor matches,
/// we measure pure Vectorscan automaton traversal without callback overhead.
///
/// Key configuration choices:
/// - **No transforms**: Disables base64/URL decode paths entirely
/// - **ManualOnly anchor policy**: Uses only the explicit anchor, no derivation
/// - **Single rule**: Minimal automaton complexity
///
/// The result approximates the Vectorscan library's theoretical throughput
/// ceiling for our pattern structure.
fn minimal_engine() -> Engine {
    let rules = vec![RuleSpec {
        name: "impossible-pattern",
        // Anchor that cannot appear in random/ascii data
        anchors: &[b"\xFF\xFE\xFD\xFC"],
        radius: 64,
        validator: scanner_engine::ValidatorKind::None,
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

    let transforms = vec![]; // No transforms for ceiling test
    let tuning = demo_tuning();

    Engine::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::ManualOnly)
}

/// Create engine with transforms disabled for prefilter-only testing.
///
/// Uses the full rule set (derived anchors, all validators) but disables
/// transform processing by setting `max_transform_depth = 0`. This isolates
/// the cost of:
/// - Vectorscan anchor matching
/// - Regex validation on anchor windows
/// - Offline validation on confirmed findings (format checks, checksums)
///
/// ...without the additional overhead of detecting and decoding base64/URL
/// content. Useful for measuring Tiers 2 and 3.
fn engine_no_transforms() -> Engine {
    let tuning = Tuning {
        max_transform_depth: 0, // Disable transform processing
        ..demo_tuning()
    };
    scanner_engine::demo_engine_with_anchor_mode_and_tuning(AnchorMode::Derived, tuning)
}

/// Standard demo engine with full rule set.
///
/// This is the production configuration: derived anchors, all validators,
/// and full transform support (base64, URL decoding). Use this engine
/// for representative end-to-end throughput measurements.
fn full_engine() -> Engine {
    demo_engine_with_anchor_mode(AnchorMode::Derived)
}

// ============================================================================
// Tier 1: Vectorscan Ceiling (No Hits)
// ============================================================================

/// Measures the theoretical throughput ceiling with zero pattern matches.
///
/// # What we're measuring
///
/// Pure Vectorscan automaton traversal: the scanner processes every byte
/// through the DFA but never invokes callbacks because the impossible anchor
/// pattern never matches.
///
/// # Expected results
///
/// 40-80 GB/s, limited primarily by memory bandwidth. This establishes the
/// upper bound against which other tiers are compared. If Tier 1 throughput
/// is significantly below memory bandwidth, there's overhead in the scan loop
/// itself (scratch allocation, function call overhead, etc.).
///
/// # Buffer size variation
///
/// We test multiple buffer sizes to observe:
/// - Small buffers: Per-call overhead dominates
/// - Large buffers: Steady-state throughput, memory hierarchy effects
fn bench_tier1_ceiling(c: &mut Criterion) {
    let mut group = c.benchmark_group("tier1_ceiling");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(5));

    let engine = minimal_engine();
    let mut scratch = engine.new_scratch();

    // Test with random bytes - should have zero pattern hits
    for &(size, name) in BUFFER_SIZES {
        let data = gen_random_bytes(size, 0x1234_5678);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("random", name), &data, |b, data| {
            b.iter(|| {
                let hits = engine.scan_chunk(black_box(data), &mut scratch);
                black_box(hits.len())
            })
        });
    }

    // Also test with clean ASCII
    for &(size, name) in BUFFER_SIZES {
        let data = gen_clean_ascii(size, 0x8765_4321);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("clean_ascii", name), &data, |b, data| {
            b.iter(|| {
                let hits = engine.scan_chunk(black_box(data), &mut scratch);
                black_box(hits.len())
            })
        });
    }

    group.finish();
}

// ============================================================================
// Tier 2: Prefilter Hits, Fast Reject
// ============================================================================

/// Measures throughput when anchors match but regexes don't.
///
/// # What we're measuring
///
/// The "false positive" cost of the prefilter strategy. Vectorscan finds
/// anchor matches (e.g., "AKIA", "ghp_", "secret"), invokes our callback,
/// but the surrounding context fails regex validation.
///
/// This is the common case in real codebases: lots of strings that *look*
/// like they could be secrets but aren't.
///
/// # Hit interval parameter
///
/// We vary how frequently anchors appear (every 1KB, 4KB, 16KB, 64KB) to
/// model different content densities:
/// - 64KB: Very clean code, rare false positives
/// - 1KB: Dense config files or logs with many keywords
///
/// # Expected results
///
/// 10-30 GB/s. The gap from Tier 1 reveals callback + regex overhead.
fn bench_tier2_prefilter(c: &mut Criterion) {
    let mut group = c.benchmark_group("tier2_prefilter");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(5));

    let engine = engine_no_transforms();
    let mut scratch = engine.new_scratch();

    // Sparse hits - anchors present but regex won't match
    let hit_intervals = [
        (64 * 1024, "64KB_interval"),
        (16 * 1024, "16KB_interval"),
        (4 * 1024, "4KB_interval"),
        (1024, "1KB_interval"),
    ];

    for &(interval, interval_name) in &hit_intervals {
        let data = gen_sparse_anchor_hits(PRIMARY_SIZE, 0xABCD_EF01, interval);
        group.throughput(Throughput::Bytes(PRIMARY_SIZE as u64));

        group.bench_with_input(
            BenchmarkId::new("sparse_anchors", interval_name),
            &data,
            |b, data| {
                b.iter(|| {
                    let hits = engine.scan_chunk(black_box(data), &mut scratch);
                    black_box(hits.len())
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Tier 3: Full Validation Path
// ============================================================================

/// Measures throughput when patterns match and run full validation.
///
/// # What we're measuring
///
/// The complete detection pipeline for structurally-valid secrets:
/// 1. Vectorscan anchor match
/// 2. Window extraction
/// 3. Regex validation (matches)
/// 4. Validator execution (checksum, entropy, format checks)
/// 5. Hit recording
///
/// # Pattern types
///
/// We test both AWS keys (`AKIA...`) and GitHub tokens (`ghp_...`) because:
/// - They have different regex complexity
/// - Different validator logic (AWS has no checksum, GitHub PATs do)
/// - Different token lengths affecting window sizes
///
/// # Expected results
///
/// 2-10 GB/s. Validators add measurable overhead, especially checksums.
fn bench_tier3_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("tier3_validation");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(5));

    let engine = engine_no_transforms();
    let mut scratch = engine.new_scratch();

    // AWS key format matches
    let intervals = [
        (64 * 1024, "sparse_64KB"),
        (16 * 1024, "moderate_16KB"),
        (4 * 1024, "dense_4KB"),
    ];

    for &(interval, name) in &intervals {
        let data = gen_aws_key_hits(PRIMARY_SIZE, 0xFEDC_BA98, interval);
        group.throughput(Throughput::Bytes(PRIMARY_SIZE as u64));

        group.bench_with_input(BenchmarkId::new("aws_keys", name), &data, |b, data| {
            b.iter(|| {
                let hits = engine.scan_chunk(black_box(data), &mut scratch);
                black_box(hits.len())
            })
        });
    }

    // GitHub token format matches
    for &(interval, name) in &intervals {
        let data = gen_github_token_hits(PRIMARY_SIZE, 0x1357_9BDF, interval);
        group.throughput(Throughput::Bytes(PRIMARY_SIZE as u64));

        group.bench_with_input(BenchmarkId::new("github_tokens", name), &data, |b, data| {
            b.iter(|| {
                let hits = engine.scan_chunk(black_box(data), &mut scratch);
                black_box(hits.len())
            })
        });
    }

    group.finish();
}

// ============================================================================
// Tier 4: Transform-Heavy Workloads
// ============================================================================

/// Measures throughput for encoded content requiring transforms.
///
/// # What we're measuring
///
/// The full transform pipeline:
/// 1. Detect encoded regions (base64 alphabet runs, % escapes)
/// 2. Allocate decode buffer
/// 3. Decode content
/// 4. Recursively scan decoded content
/// 5. Map hits back to original offsets
///
/// This is the slowest tier because it does 2x+ the scanning work per byte.
///
/// # Workload variants
///
/// - **base64_secrets**: Encoded secrets that will be found after decode
/// - **base64_noise**: Encoded garbage testing gating effectiveness
/// - **url_encoded**: Percent-encoded content at various densities
///
/// # Expected results
///
/// 0.5-4 GB/s. Heavily dependent on transform gating effectiveness.
fn bench_tier4_transforms(c: &mut Criterion) {
    let mut group = c.benchmark_group("tier4_transforms");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(5));

    let engine = full_engine();
    let mut scratch = engine.new_scratch();

    // Base64 with embedded secrets
    let secret_intervals = [
        (64 * 1024, "sparse_64KB"),
        (16 * 1024, "moderate_16KB"),
        (4 * 1024, "dense_4KB"),
    ];

    for &(interval, name) in &secret_intervals {
        let data = gen_base64_with_secrets(PRIMARY_SIZE, 0x2468_ACE0, interval);
        group.throughput(Throughput::Bytes(PRIMARY_SIZE as u64));

        group.bench_with_input(
            BenchmarkId::new("base64_secrets", name),
            &data,
            |b, data| {
                b.iter(|| {
                    let hits = engine.scan_chunk(black_box(data), &mut scratch);
                    black_box(hits.len())
                })
            },
        );
    }

    // Base64 noise (no secrets - tests gating effectiveness)
    let data = gen_base64_noise(PRIMARY_SIZE, 0xDEAD_BEEF);
    group.throughput(Throughput::Bytes(PRIMARY_SIZE as u64));
    group.bench_with_input(BenchmarkId::new("base64_noise", "4MB"), &data, |b, data| {
        b.iter(|| {
            let hits = engine.scan_chunk(black_box(data), &mut scratch);
            black_box(hits.len())
        })
    });

    // URL encoded content
    let escape_densities = [(0.05, "5pct"), (0.15, "15pct"), (0.30, "30pct")];

    for &(density, name) in &escape_densities {
        let data = gen_url_encoded(PRIMARY_SIZE, 0xCAFE_BABE, density);
        group.throughput(Throughput::Bytes(PRIMARY_SIZE as u64));

        group.bench_with_input(BenchmarkId::new("url_encoded", name), &data, |b, data| {
            b.iter(|| {
                let hits = engine.scan_chunk(black_box(data), &mut scratch);
                black_box(hits.len())
            })
        });
    }

    group.finish();
}

// ============================================================================
// Comparative Benchmarks
// ============================================================================

/// Side-by-side comparison of all workloads with the production engine.
///
/// Unlike the tier-specific benchmarks, this uses a single engine configuration
/// (full production settings) and runs all workloads for direct comparison.
/// Results show relative performance across content types.
///
/// Use this benchmark to answer: "How does throughput vary across real-world
/// content types with our actual production configuration?"
fn bench_workload_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("workload_comparison");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(5));
    group.throughput(Throughput::Bytes(PRIMARY_SIZE as u64));

    let engine = full_engine();
    let mut scratch = engine.new_scratch();

    // Generate all workloads
    let workloads = [
        Workload {
            name: "random_bytes",
            // Pure random - no hits expected
            data: gen_random_bytes(PRIMARY_SIZE, 0x1111),
        },
        Workload {
            name: "clean_ascii",
            // Clean ASCII text - minimal hits
            data: gen_clean_ascii(PRIMARY_SIZE, 0x2222),
        },
        Workload {
            name: "sparse_anchors",
            // Anchor hits every 16KB, no regex match
            data: gen_sparse_anchor_hits(PRIMARY_SIZE, 0x3333, 16 * 1024),
        },
        Workload {
            name: "moderate_secrets",
            // AWS keys every 16KB
            data: gen_aws_key_hits(PRIMARY_SIZE, 0x4444, 16 * 1024),
        },
        Workload {
            name: "base64_noise",
            // Base64 content, no secrets
            data: gen_base64_noise(PRIMARY_SIZE, 0x5555),
        },
        Workload {
            name: "base64_secrets",
            // Base64 with secrets every 16KB
            data: gen_base64_with_secrets(PRIMARY_SIZE, 0x6666, 16 * 1024),
        },
        Workload {
            name: "mixed_realistic",
            // Simulated code repository content
            data: gen_mixed_realistic(PRIMARY_SIZE, 0x7777),
        },
    ];

    for workload in &workloads {
        group.bench_with_input(
            BenchmarkId::new("full_engine", workload.name),
            &workload.data,
            |b, data| {
                b.iter(|| {
                    let hits = engine.scan_chunk(black_box(data), &mut scratch);
                    black_box(hits.len())
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Buffer Size Scaling
// ============================================================================

/// Measures how throughput scales with input buffer size.
///
/// # Why buffer size matters
///
/// Smaller buffers expose per-call overhead (scratch setup, function calls),
/// while larger buffers reveal steady-state throughput and memory hierarchy
/// effects (L3 cache misses, DRAM bandwidth limits).
///
/// Real-world usage involves a mix: many small files (configs, READMEs) and
/// occasional large files (minified JS, data dumps). Understanding the
/// throughput curve helps choose optimal chunking strategies.
///
/// # Buffer sizes tested
///
/// 64KB → 16MB, spanning:
/// - L2 cache resident (~256KB)
/// - L3 cache resident (~1-4MB)
/// - DRAM-bound (>8MB on most systems)
fn bench_buffer_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_scaling");
    group.sampling_mode(SamplingMode::Flat);
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(3));

    let engine = full_engine();
    let mut scratch = engine.new_scratch();

    // Test how throughput scales with buffer size for different workloads
    for &(size, size_name) in BUFFER_SIZES {
        group.throughput(Throughput::Bytes(size as u64));

        // Random bytes
        let data = gen_random_bytes(size, 0xAAAA);
        group.bench_with_input(BenchmarkId::new("random", size_name), &data, |b, data| {
            b.iter(|| {
                let hits = engine.scan_chunk(black_box(data), &mut scratch);
                black_box(hits.len())
            })
        });

        // Mixed realistic
        let data = gen_mixed_realistic(size, 0xBBBB);
        group.bench_with_input(
            BenchmarkId::new("mixed_realistic", size_name),
            &data,
            |b, data| {
                b.iter(|| {
                    let hits = engine.scan_chunk(black_box(data), &mut scratch);
                    black_box(hits.len())
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(tier1_benches, bench_tier1_ceiling,);

criterion_group!(tier2_benches, bench_tier2_prefilter,);

criterion_group!(tier3_benches, bench_tier3_validation,);

criterion_group!(tier4_benches, bench_tier4_transforms,);

criterion_group!(
    comparison_benches,
    bench_workload_comparison,
    bench_buffer_scaling,
);

criterion_main!(
    tier1_benches,
    tier2_benches,
    tier3_benches,
    tier4_benches,
    comparison_benches,
);
