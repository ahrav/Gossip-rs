//! Archive scanning throughput benchmarks.
//!
//! Measures decompressed bytes/sec through the archive scan pipeline using a
//! no-op sink, isolating scan + budget-charging overhead from engine/detection
//! costs. Three benchmark groups target different bottlenecks:
//!
//! - **`targz_scan`** — end-to-end gzip throughput across a matrix of entry
//!   counts and sizes, revealing per-entry overhead vs. bulk-copy throughput.
//! - **`tarbz2_scan`** — matching bzip2 throughput sweep for direct comparison
//!   against gzip. Useful for quantifying bzip2 (`bzip2-sys`, C libbzip2) vs.
//!   gzip (`zlib-ng`, C) decompression throughput differences.
//! - **`budget_overhead`** — worst-case per-entry cost with 10 000 × 64 B
//!   entries, where header parsing and budget charging dominate wall time.
//!
//! All archives are built deterministically in-memory (xorshift64 PRNG, fixed
//! seed) so results are reproducible across runs without touching the
//! filesystem.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::io::{self, Cursor, Read, Write};

use scanner_scheduler::archive::{
    ArchiveConfig, ArchiveEnd, ArchiveEntrySink, ArchiveScratch, ArchiveStats, EntryChunk,
    EntryMeta, scan_bzip2_stream, scan_tarbz2_stream, scan_targz_stream,
};

/// Discards all entry data, accumulating only a byte count.
///
/// Used to isolate scan-loop and budget-charging overhead from any
/// engine/detection cost. The `total_bytes` counter lets the benchmark
/// verify that the expected payload volume was delivered.
struct NullSink {
    total_bytes: u64,
}

impl NullSink {
    fn new() -> Self {
        Self { total_bytes: 0 }
    }
}

impl ArchiveEntrySink for NullSink {
    type Error = io::Error;

    fn on_entry_start(&mut self, _meta: &EntryMeta<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn on_entry_chunk(&mut self, chunk: EntryChunk<'_>) -> Result<(), Self::Error> {
        self.total_bytes += chunk.new_bytes_len as u64;
        Ok(())
    }

    fn on_entry_end(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Xorshift64 PRNG for reproducible, dependency-free random payloads.
///
/// The (13, 7, 17) shift triple is Marsaglia's original xorshift64 variant.
/// We only need non-compressible fill data — statistical quality beyond that
/// is irrelevant, so a fast, simple generator suffices.
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
}

/// Build a POSIX (ustar) tar header for a regular file.
///
/// Constructs a 512-byte header block in-place following the POSIX.1-1988
/// ustar layout. Field offsets (see IEEE Std 1003.1-1988 §10.1.1):
///
/// | Offset | Len | Field       |
/// |--------|-----|-------------|
/// |   0    | 100 | name        |
/// | 100    |   8 | mode        |
/// | 108    |   8 | uid         |
/// | 116    |   8 | gid         |
/// | 124    |  12 | size (octal)|
/// | 136    |  12 | mtime       |
/// | 148    |   8 | checksum    |
/// | 156    |   1 | typeflag    |
/// | 257    |   6 | magic       |
/// | 263    |   2 | version     |
///
/// The checksum is computed as the unsigned sum of all 512 bytes with the
/// checksum field itself treated as ASCII spaces (the initial fill value).
fn build_tar_header(name: &[u8], size: u64) -> [u8; 512] {
    let mut hdr = [0u8; 512];

    // name field (0..100)
    let name_len = name.len().min(100);
    hdr[..name_len].copy_from_slice(&name[..name_len]);

    // mode (100..108)
    hdr[100..108].copy_from_slice(b"0000644\0");
    // uid (108..116)
    hdr[108..116].copy_from_slice(b"0001000\0");
    // gid (116..124)
    hdr[116..124].copy_from_slice(b"0001000\0");

    // size in octal (124..136)
    let mut size_field = [b'0'; 11];
    let mut v = size;
    for i in (0..11).rev() {
        size_field[i] = b'0' + ((v & 7) as u8);
        v >>= 3;
    }
    hdr[124..135].copy_from_slice(&size_field);
    hdr[135] = 0;

    // mtime (136..148)
    hdr[136..148].copy_from_slice(b"00000000000\0");

    // checksum placeholder (148..156) - spaces
    for b in &mut hdr[148..156] {
        *b = b' ';
    }

    // typeflag: regular file
    hdr[156] = b'0';

    // ustar magic
    hdr[257..263].copy_from_slice(b"ustar\0");
    hdr[263..265].copy_from_slice(b"00");

    // compute checksum
    let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
    let chk = format!("{:06o}\0 ", sum);
    hdr[148..156].copy_from_slice(chk.as_bytes());

    hdr
}

/// Bytes of zero-padding needed after `size` bytes to reach a 512-byte
/// boundary (tar records are always block-aligned).
fn tar_pad(size: u64) -> usize {
    let rem = size % 512;
    if rem == 0 { 0 } else { (512 - rem) as usize }
}

/// Build a deterministic, uncompressed tar archive in memory.
///
/// Each entry is: 512-byte header ‖ payload ‖ zero-pad to 512-byte boundary.
/// The archive terminates with two 512-byte zero blocks (1024 bytes) per the
/// tar end-of-archive marker convention.
fn build_tar(entry_count: usize, entry_size: usize, seed: u64) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut tar = Vec::with_capacity(entry_count * (512 + entry_size + 512));

    let mut payload = vec![0u8; entry_size];

    for i in 0..entry_count {
        // Generate deterministic filename
        let name = format!("entry_{:06}.bin", i);
        let hdr = build_tar_header(name.as_bytes(), entry_size as u64);
        tar.extend_from_slice(&hdr);

        // Generate deterministic payload
        rng.fill_bytes(&mut payload);
        tar.extend_from_slice(&payload);

        // Pad to 512-byte boundary
        let pad = tar_pad(entry_size as u64);
        if pad > 0 {
            tar.extend_from_slice(&vec![0u8; pad]);
        }
    }

    // Two zero blocks to signal end of archive
    tar.extend_from_slice(&[0u8; 1024]);
    tar
}

/// Gzip-compress a tar archive in memory.
fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

/// Bzip2-compress a byte slice in memory using the fastest level (1).
///
/// Level 1 minimises archive-construction time in benchmarks so that setup
/// cost does not dominate the measurement. The decompression speed — which is
/// what the benchmark actually measures — is largely independent of the
/// compression level used during encoding.
fn bzip2_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(1));
    encoder.write_all(data).expect("bzip2 write");
    encoder.finish().expect("bzip2 finish")
}

/// Build a deterministic tar.gz archive.
fn build_targz(entry_count: usize, entry_size: usize, seed: u64) -> Vec<u8> {
    let tar = build_tar(entry_count, entry_size, seed);
    gzip_compress(&tar)
}

/// Build a deterministic tar.bz2 archive.
fn build_tarbz2(entry_count: usize, entry_size: usize, seed: u64) -> Vec<u8> {
    let tar = build_tar(entry_count, entry_size, seed);
    bzip2_compress(&tar)
}

/// Build a standalone bzip2-compressed blob (no tar wrapper).
fn build_bzip2_standalone(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut payload = vec![0u8; size];
    rng.fill_bytes(&mut payload);
    bzip2_compress(&payload)
}

/// Compute total decompressed payload bytes for verification.
fn expected_decompressed(entry_count: usize, entry_size: usize) -> u64 {
    (entry_count as u64) * (entry_size as u64)
}

/// Zero-length, no-op [`ZipSource`] satisfying the generic parameter of
/// [`ArchiveScratch`]. These benchmarks only exercise tar.{gz,bz2} paths, so
/// the zip source is never read — but the type parameter must be filled.
#[derive(Clone)]
struct NullZipSource;

impl Read for NullZipSource {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl io::Seek for NullZipSource {
    fn seek(&mut self, _pos: io::SeekFrom) -> io::Result<u64> {
        Ok(0)
    }
}

impl scanner_scheduler::archive::formats::ZipSource for NullZipSource {
    fn len(&self) -> io::Result<u64> {
        Ok(0)
    }
    fn try_clone(&self) -> io::Result<Self> {
        Ok(NullZipSource)
    }
}

/// Throughput sweep across entry count × entry size.
///
/// The matrix is chosen to tease apart two cost centres:
///
/// - **Small entries (1 KB)**: per-entry overhead dominates — header parsing,
///   budget charging, sink callbacks.
/// - **Large entries (64 KB, 1 MB)**: bulk memcpy / decompression throughput
///   dominates; per-entry costs are amortized.
///
/// Criterion reports `Throughput::Bytes` as *decompressed* payload bytes/sec,
/// so gzip decompression cost is included but tar metadata is not.
fn bench_targz_throughput(c: &mut Criterion) {
    let configs: &[(usize, usize, &str)] = &[
        (100, 1024, "100x1KB"),
        (100, 64 * 1024, "100x64KB"),
        (10, 1024 * 1024, "10x1MB"),
        (1000, 1024, "1000x1KB"),
        (1000, 64 * 1024, "1000x64KB"),
    ];

    let archive_cfg = ArchiveConfig {
        enabled: true,
        max_archive_depth: 4,
        max_entries_per_archive: 100_000,
        max_uncompressed_bytes_per_entry: 256 * 1024 * 1024,
        max_total_uncompressed_bytes_per_archive: 1024 * 1024 * 1024,
        max_total_uncompressed_bytes_per_root: 2048 * 1024 * 1024,
        max_archive_metadata_bytes: 64 * 1024 * 1024,
        max_inflation_ratio: 1000,
        ..ArchiveConfig::default()
    };

    // 256 KB chunk size mirrors the production default; overlap=0 because
    // there is no pattern-matching engine that needs cross-chunk context.
    let chunk_size = 256 * 1024;
    let overlap = 0;

    let mut group = c.benchmark_group("targz_scan");

    for &(entry_count, entry_size, label) in configs {
        let targz = build_targz(entry_count, entry_size, 0xDEAD_BEEF_CAFE_1234);
        let decompressed_total = expected_decompressed(entry_count, entry_size);

        group.throughput(Throughput::Bytes(decompressed_total));
        group.bench_with_input(BenchmarkId::new("throughput", label), &targz, |b, targz| {
            // Scratch and sink are allocated once outside the hot loop so
            // the measured time reflects steady-state reuse, not first-call
            // allocation.
            let mut scratch: ArchiveScratch<NullZipSource> =
                ArchiveScratch::new(&archive_cfg, chunk_size, overlap);
            let mut sink = NullSink::new();
            let mut stats = ArchiveStats::default();

            b.iter(|| {
                sink.total_bytes = 0;
                let reader = Cursor::new(black_box(targz.as_slice()));
                let result: Result<ArchiveEnd, io::Error> = scan_targz_stream(
                    reader,
                    b"/bench/test.tar.gz",
                    &archive_cfg,
                    &mut scratch,
                    &mut sink,
                    &mut stats,
                );
                black_box(result.unwrap());
                black_box(sink.total_bytes);
                debug_assert_eq!(
                    sink.total_bytes, decompressed_total,
                    "sink byte count mismatch: scan may have dropped data"
                );
            });
        });
    }

    group.finish();
}

/// Bzip2 throughput sweep, mirroring [`bench_targz_throughput`] for direct
/// comparison.
///
/// Uses the same tar payloads compressed with bzip2 (level 1) instead of gzip.
/// Smaller entry counts keep benchmark setup time reasonable — bzip2
/// compression is ~5x slower than gzip, so building the archives takes longer.
///
/// Run both groups to compare:
/// ```bash
/// cargo bench --bench archive_throughput -- "targz_scan|tarbz2_scan"
/// ```
fn bench_tarbz2_throughput(c: &mut Criterion) {
    let configs: &[(usize, usize, &str)] = &[
        (100, 1024, "100x1KB"),
        (100, 64 * 1024, "100x64KB"),
        (10, 1024 * 1024, "10x1MB"),
    ];

    let archive_cfg = ArchiveConfig {
        enabled: true,
        max_archive_depth: 4,
        max_entries_per_archive: 100_000,
        max_uncompressed_bytes_per_entry: 256 * 1024 * 1024,
        max_total_uncompressed_bytes_per_archive: 1024 * 1024 * 1024,
        max_total_uncompressed_bytes_per_root: 2048 * 1024 * 1024,
        max_archive_metadata_bytes: 64 * 1024 * 1024,
        max_inflation_ratio: 1000,
        ..ArchiveConfig::default()
    };

    let chunk_size = 256 * 1024;
    let overlap = 0;

    let mut group = c.benchmark_group("tarbz2_scan");

    for &(entry_count, entry_size, label) in configs {
        let tarbz2 = build_tarbz2(entry_count, entry_size, 0xDEAD_BEEF_CAFE_1234);
        let decompressed_total = expected_decompressed(entry_count, entry_size);

        group.throughput(Throughput::Bytes(decompressed_total));
        group.bench_with_input(
            BenchmarkId::new("throughput", label),
            &tarbz2,
            |b, tarbz2| {
                let mut scratch: ArchiveScratch<NullZipSource> =
                    ArchiveScratch::new(&archive_cfg, chunk_size, overlap);
                let mut sink = NullSink::new();
                let mut stats = ArchiveStats::default();

                b.iter(|| {
                    sink.total_bytes = 0;
                    let reader = Cursor::new(black_box(tarbz2.as_slice()));
                    let result: Result<ArchiveEnd, io::Error> = scan_tarbz2_stream(
                        reader,
                        b"/bench/test.tar.bz2",
                        &archive_cfg,
                        &mut scratch,
                        &mut sink,
                        &mut stats,
                    );
                    black_box(result.unwrap());
                    black_box(sink.total_bytes);
                    debug_assert_eq!(
                        sink.total_bytes, decompressed_total,
                        "sink byte count mismatch: scan may have dropped data"
                    );
                });
            },
        );
    }

    group.finish();
}

/// Standalone bzip2 throughput (no tar layer).
///
/// Measures raw bzip2 decompression + scan-loop overhead without tar header
/// parsing. Three sizes span the range from L2-resident to main-memory:
///
/// - **64 KB**: fits in L2; measures decode + budget overhead at small scale.
/// - **1 MB**: moderate working set; typical single-file decompression.
/// - **10 MB**: large blob; bulk throughput measurement.
fn bench_bzip2_throughput(c: &mut Criterion) {
    let configs: &[(usize, &str)] = &[
        (64 * 1024, "64KB"),
        (1024 * 1024, "1MB"),
        (10 * 1024 * 1024, "10MB"),
    ];

    let archive_cfg = ArchiveConfig {
        enabled: true,
        max_archive_depth: 4,
        max_entries_per_archive: 100_000,
        max_uncompressed_bytes_per_entry: 256 * 1024 * 1024,
        max_total_uncompressed_bytes_per_archive: 1024 * 1024 * 1024,
        max_total_uncompressed_bytes_per_root: 2048 * 1024 * 1024,
        max_archive_metadata_bytes: 64 * 1024 * 1024,
        max_inflation_ratio: 1000,
        ..ArchiveConfig::default()
    };

    let chunk_size = 256 * 1024;
    let overlap = 0;

    let mut group = c.benchmark_group("bzip2_scan");

    for &(size, label) in configs {
        let bz2 = build_bzip2_standalone(size, 0xDEAD_BEEF_CAFE_B220);
        let decompressed_total = size as u64;

        group.throughput(Throughput::Bytes(decompressed_total));
        group.bench_with_input(BenchmarkId::new("throughput", label), &bz2, |b, bz2| {
            let mut scratch: ArchiveScratch<NullZipSource> =
                ArchiveScratch::new(&archive_cfg, chunk_size, overlap);
            let mut sink = NullSink::new();
            let mut stats = ArchiveStats::default();

            b.iter(|| {
                sink.total_bytes = 0;
                let reader = Cursor::new(black_box(bz2.as_slice()));
                let result: Result<ArchiveEnd, io::Error> = scan_bzip2_stream(
                    reader,
                    b"/bench/test.bz2",
                    &archive_cfg,
                    &mut scratch,
                    &mut sink,
                    &mut stats,
                );
                black_box(result.unwrap());
                black_box(sink.total_bytes);
                debug_assert_eq!(
                    sink.total_bytes, decompressed_total,
                    "sink byte count mismatch: scan may have dropped data"
                );
            });
        });
    }

    group.finish();
}

/// Worst-case per-entry budget-charging overhead.
///
/// 10 000 entries × 64 B each: the payload is negligible so nearly all time
/// is spent in header parsing, budget checks, and sink dispatch.  This is the
/// scenario where branchless budget arithmetic matters most — a branch
/// misprediction per entry at this scale is visible in wall-clock time.
fn bench_budget_overhead(c: &mut Criterion) {
    let archive_cfg = ArchiveConfig {
        enabled: true,
        max_archive_depth: 4,
        max_entries_per_archive: 100_000,
        max_uncompressed_bytes_per_entry: 256 * 1024 * 1024,
        max_total_uncompressed_bytes_per_archive: 1024 * 1024 * 1024,
        max_total_uncompressed_bytes_per_root: 2048 * 1024 * 1024,
        max_archive_metadata_bytes: 64 * 1024 * 1024,
        max_inflation_ratio: 1000,
        ..ArchiveConfig::default()
    };

    let chunk_size = 256 * 1024;
    let overlap = 0;

    // Many small entries: high per-entry overhead ratio
    let targz_small = build_targz(10_000, 64, 0x1234_5678_9ABC_DEF0);
    let decompressed_small = expected_decompressed(10_000, 64);

    let mut group = c.benchmark_group("budget_overhead");
    group.throughput(Throughput::Bytes(decompressed_small));
    group.bench_function("10000x64B", |b| {
        let mut scratch: ArchiveScratch<NullZipSource> =
            ArchiveScratch::new(&archive_cfg, chunk_size, overlap);
        let mut sink = NullSink::new();
        let mut stats = ArchiveStats::default();

        b.iter(|| {
            sink.total_bytes = 0;
            let reader = Cursor::new(black_box(targz_small.as_slice()));
            let result: Result<ArchiveEnd, io::Error> = scan_targz_stream(
                reader,
                b"/bench/small.tar.gz",
                &archive_cfg,
                &mut scratch,
                &mut sink,
                &mut stats,
            );
            black_box(result.unwrap());
            black_box(sink.total_bytes);
            debug_assert!(sink.total_bytes > 0, "sink received no bytes");
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_targz_throughput,
    bench_tarbz2_throughput,
    bench_bzip2_throughput,
    bench_budget_overhead,
);
criterion_main!(benches);
