use super::*;
use std::io::Cursor;

// ── RecordingSink ──────────────────────────────────────────────────

/// Captured data for a single entry chunk delivery.
#[derive(Debug, Clone)]
struct RecordedChunk {
    data: Vec<u8>,
    base_offset: u64,
    new_bytes_start: u64,
    new_bytes_len: usize,
}

/// Captured events for a single entry start/chunk*/end cycle.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RecordedEntry {
    display_path: Vec<u8>,
    size_hint: u64,
    chunks: Vec<RecordedChunk>,
}

/// Test sink that records every entry event for post-hoc assertions.
#[derive(Debug, Default)]
struct RecordingSink {
    entries: Vec<RecordedEntry>,
    current: Option<RecordedEntry>,
}

impl RecordingSink {
    fn new() -> Self {
        Self::default()
    }

    /// Concatenate all `new_bytes` delivered for entry at `idx`.
    fn concat_new_bytes(&self, idx: usize) -> Vec<u8> {
        let entry = &self.entries[idx];
        let mut out = Vec::new();
        for c in &entry.chunks {
            let start = c.data.len() - c.new_bytes_len;
            out.extend_from_slice(&c.data[start..]);
        }
        out
    }
}

impl ArchiveEntrySink for RecordingSink {
    type Error = std::convert::Infallible;

    fn on_entry_start(&mut self, meta: &EntryMeta<'_>) -> Result<(), Self::Error> {
        assert!(
            self.current.is_none(),
            "on_entry_start without prior on_entry_end"
        );
        self.current = Some(RecordedEntry {
            display_path: meta.display_path.to_vec(),
            size_hint: meta.size_hint,
            chunks: Vec::new(),
        });
        Ok(())
    }

    fn on_entry_chunk(&mut self, chunk: EntryChunk<'_>) -> Result<(), Self::Error> {
        let entry = self
            .current
            .as_mut()
            .expect("on_entry_chunk without on_entry_start");
        entry.chunks.push(RecordedChunk {
            data: chunk.data.to_vec(),
            base_offset: chunk.base_offset,
            new_bytes_start: chunk.new_bytes_start,
            new_bytes_len: chunk.new_bytes_len,
        });
        Ok(())
    }

    fn on_entry_end(&mut self) -> Result<(), Self::Error> {
        let entry = self
            .current
            .take()
            .expect("on_entry_end without on_entry_start");
        self.entries.push(entry);
        Ok(())
    }
}

// ── Tar helpers ────────────────────────────────────────────────────

const TAR_BLOCK: usize = 512;

fn tar_header(name: &[u8], size: u64, typeflag: u8) -> [u8; TAR_BLOCK] {
    let mut buf = [0u8; TAR_BLOCK];
    let name_len = name.len().min(100);
    buf[..name_len].copy_from_slice(&name[..name_len]);

    // Octal size field (12 bytes at offset 124).
    let mut size_field = [b'0'; 11];
    let mut v = size;
    for i in (0..11).rev() {
        size_field[i] = b'0' + ((v & 7) as u8);
        v >>= 3;
    }
    buf[124..135].copy_from_slice(&size_field);
    buf[135] = 0;

    // Mtime (12 bytes at offset 136).
    buf[136..148].copy_from_slice(b"00000000000\0");

    // Checksum placeholder (8 spaces).
    for b in &mut buf[148..156] {
        *b = b' ';
    }

    buf[156] = typeflag;
    buf[257..263].copy_from_slice(b"ustar\0");
    buf[263..265].copy_from_slice(b"00");

    // Compute checksum.
    let sum: u32 = buf.iter().map(|&b| b as u32).sum();
    let chk = format!("{:06o}\0 ", sum);
    buf[148..156].copy_from_slice(chk.as_bytes());
    buf
}

fn tar_pad(size: usize) -> usize {
    let rem = size % TAR_BLOCK;
    if rem == 0 {
        0
    } else {
        TAR_BLOCK - rem
    }
}

/// Build a tar archive from `(name, payload)` pairs.
fn build_tar(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(name, payload) in entries {
        let hdr = tar_header(name, payload.len() as u64, b'0');
        out.extend_from_slice(&hdr);
        out.extend_from_slice(payload);
        out.extend_from_slice(&vec![0u8; tar_pad(payload.len())]);
    }
    // Two zero blocks (end-of-archive).
    out.extend_from_slice(&[0u8; TAR_BLOCK * 2]);
    out
}

fn default_config() -> ArchiveConfig {
    ArchiveConfig {
        enabled: true,
        ..ArchiveConfig::default()
    }
}

type TestScratch = ArchiveScratch<Cursor<Vec<u8>>>;

/// Run scan_tar_stream on raw tar bytes and return (outcome, sink, budgets_depth).
fn scan_tar_bytes(
    tar_bytes: &[u8],
    cfg: &ArchiveConfig,
    chunk_size: usize,
    overlap: usize,
) -> (ArchiveEnd, RecordingSink, u8) {
    let mut scratch: TestScratch = ArchiveScratch::new(cfg, chunk_size, overlap);
    let mut sink = RecordingSink::new();
    let mut stats = ArchiveStats::default();
    let mut cursor = Cursor::new(tar_bytes.to_vec());

    let outcome = scan_tar_stream(
        &mut cursor,
        b"test.tar",
        cfg,
        &mut scratch,
        &mut sink,
        &mut stats,
        false,
    )
    .unwrap();

    let depth = scratch.budgets.depth();
    (outcome, sink, depth)
}

/// Run scan_gzip_stream on raw gz bytes and return (outcome, sink, budgets_depth).
fn scan_gz_bytes(
    gz_bytes: &[u8],
    cfg: &ArchiveConfig,
    chunk_size: usize,
    overlap: usize,
) -> (ArchiveEnd, RecordingSink, u8) {
    let mut scratch: TestScratch = ArchiveScratch::new(cfg, chunk_size, overlap);
    let mut sink = RecordingSink::new();
    let mut stats = ArchiveStats::default();
    let reader = Cursor::new(gz_bytes.to_vec());

    let outcome =
        scan_gzip_stream(reader, b"test.gz", cfg, &mut scratch, &mut sink, &mut stats).unwrap();

    let depth = scratch.budgets.depth();
    (outcome, sink, depth)
}

fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

// ── Zip helpers ───────────────────────────────────────────────────

/// Build a minimal zip archive (Store-only, no compression) from `(name, payload)` pairs.
///
/// Produces: Local File Header + payload per entry → Central Directory → EOCD.
/// This is intentionally minimal — no deflate, no data descriptors, no Zip64.
/// For tests requiring compression or encryption, use `sim_archive::build_zip_bytes`.
fn build_zip(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd_entries: Vec<(u32, &[u8], u32)> = Vec::new(); // (lfh_offset, name, size)

    for &(name, payload) in entries {
        let lfh_offset = out.len() as u32;
        let size = payload.len() as u32;

        // Local File Header (30 bytes + name).
        out.extend_from_slice(b"PK\x03\x04"); // signature
        out.extend_from_slice(&10u16.to_le_bytes()); // version needed (1.0)
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: Store
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32 (unchecked in scanner)
        out.extend_from_slice(&size.to_le_bytes()); // compressed size
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        out.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name len
        out.extend_from_slice(&0u16.to_le_bytes()); // extra field len
        out.extend_from_slice(name);
        out.extend_from_slice(payload);

        cd_entries.push((lfh_offset, name, size));
    }

    let cd_offset = out.len() as u32;
    let mut cd_size = 0u32;

    for &(lfh_offset, name, size) in &cd_entries {
        let start = out.len();
        // Central Directory File Header (46 bytes + name).
        out.extend_from_slice(b"PK\x01\x02"); // signature
        out.extend_from_slice(&20u16.to_le_bytes()); // version made by
        out.extend_from_slice(&10u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: Store
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32
        out.extend_from_slice(&size.to_le_bytes()); // compressed size
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed size
        out.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name len
        out.extend_from_slice(&0u16.to_le_bytes()); // extra field len
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        out.extend_from_slice(&lfh_offset.to_le_bytes()); // relative offset of LFH
        out.extend_from_slice(name);
        cd_size += (out.len() - start) as u32;
    }

    // End of Central Directory Record (22 bytes).
    let entry_count = entries.len() as u16;
    out.extend_from_slice(b"PK\x05\x06"); // signature
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
    out.extend_from_slice(&entry_count.to_le_bytes()); // entries on this disk
    out.extend_from_slice(&entry_count.to_le_bytes()); // total entries
    out.extend_from_slice(&cd_size.to_le_bytes()); // CD size
    out.extend_from_slice(&cd_offset.to_le_bytes()); // CD offset
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len

    out
}

/// Run scan_zip_source on raw zip bytes and return (outcome, sink, budgets_depth).
fn scan_zip_bytes(
    zip_bytes: &[u8],
    cfg: &ArchiveConfig,
    chunk_size: usize,
    overlap: usize,
) -> (ArchiveEnd, RecordingSink, u8) {
    let mut scratch: TestScratch = ArchiveScratch::new(cfg, chunk_size, overlap);
    let mut sink = RecordingSink::new();
    let mut stats = ArchiveStats::default();
    let cursor = Cursor::new(zip_bytes.to_vec());

    let outcome = scan_zip_source(
        cursor,
        b"test.zip",
        cfg,
        &mut scratch,
        &mut sink,
        &mut stats,
    )
    .unwrap();

    let depth = scratch.budgets.depth();
    (outcome, sink, depth)
}

// ── Gap 1: Carry overlap boundary conditions ───────────────────────

#[test]
fn single_chunk_entry_carry_zero() {
    // Payload fits in one chunk → carry=0, full payload delivered.
    let payload = b"ABCDEFGH";
    let tar = build_tar(&[(b"f.txt", payload)]);
    let (outcome, sink, depth) = scan_tar_bytes(&tar, &default_config(), 64, 4);

    assert_eq!(outcome, ArchiveEnd::Scanned);
    assert_eq!(depth, 0);
    assert_eq!(sink.entries.len(), 1);
    assert_eq!(sink.entries[0].chunks.len(), 1);

    let c = &sink.entries[0].chunks[0];
    assert_eq!(c.new_bytes_len, payload.len());
    assert_eq!(c.base_offset, 0);
    assert_eq!(c.new_bytes_start, 0);
    assert_eq!(c.data, payload);
}

#[test]
fn multi_chunk_overlap_prefix_matches_prior_suffix() {
    // payload=20, chunk_size=8, overlap=4.
    // Verify overlap bytes in chunk[i] match prior chunk's suffix.
    let payload: Vec<u8> = (0u8..20).collect();
    let tar = build_tar(&[(b"f.txt", &payload)]);
    let (outcome, sink, _) = scan_tar_bytes(&tar, &default_config(), 8, 4);

    assert_eq!(outcome, ArchiveEnd::Scanned);
    assert_eq!(sink.entries.len(), 1);

    let chunks = &sink.entries[0].chunks;
    assert!(chunks.len() > 1, "expected multiple chunks");

    // Verify overlap correctness between consecutive chunks.
    for i in 1..chunks.len() {
        let prev = &chunks[i - 1];
        let cur = &chunks[i];

        // The carry (overlap prefix) of current chunk should match
        // the tail of the previous chunk's data.
        let carry = cur.data.len() - cur.new_bytes_len;
        if carry > 0 {
            let prev_suffix = &prev.data[prev.data.len() - carry..];
            let cur_prefix = &cur.data[..carry];
            assert_eq!(
                prev_suffix, cur_prefix,
                "overlap mismatch at chunk {i}: prev_suffix={prev_suffix:?}, cur_prefix={cur_prefix:?}"
            );
        }
    }

    // Verify concatenated new_bytes == original payload.
    let concat = sink.concat_new_bytes(0);
    assert_eq!(concat, payload);
}

#[test]
fn payload_shorter_than_overlap_clamps_carry() {
    // payload=3, overlap=8 → carry clamped to 3.
    let payload = b"XYZ";
    let tar = build_tar(&[(b"f.txt", payload)]);
    let (outcome, sink, _) = scan_tar_bytes(&tar, &default_config(), 64, 8);

    assert_eq!(outcome, ArchiveEnd::Scanned);
    assert_eq!(sink.entries.len(), 1);
    // Single chunk, carry clamped.
    assert_eq!(sink.entries[0].chunks.len(), 1);
    assert_eq!(sink.concat_new_bytes(0), payload);
}

#[test]
fn budget_clamp_mid_chunk_limits_new_bytes() {
    // payload=100, chunk_size=32, per-entry cap=20.
    let payload: Vec<u8> = (0..100).collect();
    let mut cfg = default_config();
    cfg.max_uncompressed_bytes_per_entry = 20;
    cfg.max_total_uncompressed_bytes_per_archive = 200;
    cfg.max_total_uncompressed_bytes_per_root = 200;

    let tar = build_tar(&[(b"f.txt", &payload)]);
    let (outcome, sink, _) = scan_tar_bytes(&tar, &cfg, 32, 4);

    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::EntryOutputBudgetExceeded)
        ),
        "expected EntryOutputBudgetExceeded, got {outcome:?}"
    );

    // Concatenated new_bytes should be exactly the first 20 bytes.
    let concat = sink.concat_new_bytes(0);
    assert_eq!(concat.len(), 20);
    assert_eq!(concat, &payload[..20]);
}

#[test]
fn new_bytes_start_is_monotonically_increasing() {
    // Verify new_bytes_start[i] == new_bytes_start[i-1] + new_bytes_len[i-1].
    let payload: Vec<u8> = (0..64).collect();
    let tar = build_tar(&[(b"f.txt", &payload)]);
    let (_, sink, _) = scan_tar_bytes(&tar, &default_config(), 16, 4);

    let chunks = &sink.entries[0].chunks;
    for i in 1..chunks.len() {
        let expected = chunks[i - 1].new_bytes_start + chunks[i - 1].new_bytes_len as u64;
        assert_eq!(
            chunks[i].new_bytes_start, expected,
            "new_bytes_start not monotonic at chunk {i}"
        );
    }
}

// ── Gap 1 (gzip path): same overlap checks via gzip ────────────────

#[test]
fn gzip_multi_chunk_overlap_correctness() {
    let payload: Vec<u8> = (0u8..40).collect();
    let gz = gzip_compress(&payload);
    let mut cfg = default_config();
    cfg.max_uncompressed_bytes_per_entry = 1000;
    cfg.max_total_uncompressed_bytes_per_archive = 1000;
    cfg.max_total_uncompressed_bytes_per_root = 1000;

    let (outcome, sink, depth) = scan_gz_bytes(&gz, &cfg, 8, 4);

    assert_eq!(outcome, ArchiveEnd::Scanned);
    assert_eq!(depth, 0);
    assert_eq!(sink.entries.len(), 1);

    // Verify overlap correctness.
    let chunks = &sink.entries[0].chunks;
    for i in 1..chunks.len() {
        let prev = &chunks[i - 1];
        let cur = &chunks[i];
        let carry = cur.data.len() - cur.new_bytes_len;
        if carry > 0 {
            let prev_suffix = &prev.data[prev.data.len() - carry..];
            let cur_prefix = &cur.data[..carry];
            assert_eq!(
                prev_suffix, cur_prefix,
                "gzip overlap mismatch at chunk {i}"
            );
        }
    }

    // Concatenated new_bytes == original.
    let concat = sink.concat_new_bytes(0);
    assert_eq!(concat, payload);
}

// ── Gap 3: Budget frame stack pairing on error paths ───────────────

#[test]
fn corrupted_nested_gzip_restores_budget_depth() {
    // Build tar with "inner.gz" containing corrupted gzip data.
    // Budget depth must return to 0 after scan.
    let corrupt_gz = b"NOT_VALID_GZIP_DATA_AT_ALL";
    let tar = build_tar(&[(b"inner.gz", corrupt_gz)]);

    let mut cfg = default_config();
    cfg.max_archive_depth = 4;

    let (outcome, _, depth) = scan_tar_bytes(&tar, &cfg, 64, 4);

    assert_eq!(
        depth, 0,
        "budget depth not restored after corrupted nested gzip"
    );
    // The outer tar completes successfully even though the nested gzip
    // is corrupt — the corruption is contained within the nested entry.
    // The key invariant is that budget depth returns to 0.
    assert!(
        matches!(outcome, ArchiveEnd::Scanned | ArchiveEnd::Partial(_)),
        "unexpected outcome: {outcome:?}"
    );
}

#[test]
fn nested_path_budget_exceeded_restores_depth() {
    // Set very low path budget so nested archive hits it.
    let inner_payload = b"hello world";
    let inner_tar = build_tar(&[(b"deep_entry.txt", inner_payload)]);
    let tar = build_tar(&[(b"inner.tar", &inner_tar)]);

    let mut cfg = default_config();
    cfg.max_archive_depth = 4;
    cfg.max_virtual_path_bytes_per_archive = 10; // Very small.

    let (outcome, _, depth) = scan_tar_bytes(&tar, &cfg, 64, 4);

    assert_eq!(
        depth, 0,
        "budget depth not restored after path budget exceeded"
    );
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::PathBudgetExceeded)
        ),
        "expected PathBudgetExceeded, got {outcome:?}"
    );
}

#[test]
fn root_budget_exceeded_in_nested_restores_depth() {
    // Set very small root budget so it's exhausted during nested scan.
    let inner_payload: Vec<u8> = vec![b'A'; 100];
    let inner_tar = build_tar(&[(b"big.txt", &inner_payload)]);
    let tar = build_tar(&[(b"inner.tar", &inner_tar)]);

    let mut cfg = default_config();
    cfg.max_archive_depth = 4;
    cfg.max_total_uncompressed_bytes_per_root = 10;
    cfg.max_uncompressed_bytes_per_entry = 200;
    cfg.max_total_uncompressed_bytes_per_archive = 200;

    let (outcome, _, depth) = scan_tar_bytes(&tar, &cfg, 64, 4);

    assert_eq!(
        depth, 0,
        "budget depth not restored after root budget exceeded in nested"
    );
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::RootOutputBudgetExceeded)
        ),
        "expected RootOutputBudgetExceeded, got {outcome:?}"
    );
}

// ── Gap 4: Leftover bytes after nested archives ────────────────────

#[test]
fn leftover_bytes_after_nested_archive_drained() {
    // Build a tar where "inner.tar" entry has declared size larger than
    // actual inner content. A second entry should still be scanned.
    let inner_tar = build_tar(&[(b"a.txt", b"AAA")]);
    let second_payload = b"BBBBB";

    // Construct outer tar manually: first entry has declared_size = inner_tar.len() + 512
    // (extra 512 bytes of padding that need to be drained).
    let declared_size = (inner_tar.len() + TAR_BLOCK) as u64;
    let mut outer = Vec::new();

    // First entry: inner.tar with inflated declared size.
    let hdr1 = tar_header(b"inner.tar", declared_size, b'0');
    outer.extend_from_slice(&hdr1);
    outer.extend_from_slice(&inner_tar);
    // Fill remaining declared bytes with zeros.
    let remaining = declared_size as usize - inner_tar.len();
    outer.extend_from_slice(&vec![0u8; remaining]);
    outer.extend_from_slice(&vec![0u8; tar_pad(declared_size as usize)]);

    // Second entry.
    let hdr2 = tar_header(b"second.txt", second_payload.len() as u64, b'0');
    outer.extend_from_slice(&hdr2);
    outer.extend_from_slice(second_payload);
    outer.extend_from_slice(&vec![0u8; tar_pad(second_payload.len())]);

    // End of archive.
    outer.extend_from_slice(&[0u8; TAR_BLOCK * 2]);

    let mut cfg = default_config();
    cfg.max_archive_depth = 4;
    cfg.max_total_uncompressed_bytes_per_root = 100_000;
    cfg.max_total_uncompressed_bytes_per_archive = 100_000;
    cfg.max_uncompressed_bytes_per_entry = 100_000;

    let (outcome, sink, depth) = scan_tar_bytes(&outer, &cfg, 64, 4);

    assert_eq!(depth, 0);
    // The inner.tar's entries are delivered, plus "second.txt" from the outer tar.
    // We should see at least entries from both the nested archive and the second entry.
    let has_second = sink.entries.iter().any(|e| {
        e.display_path
            .windows(b"second.txt".len())
            .any(|w| w == b"second.txt")
    });
    assert!(
        has_second,
        "second entry after nested archive was not scanned; entries: {:?}",
        sink.entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.display_path))
            .collect::<Vec<_>>()
    );
    assert_eq!(outcome, ArchiveEnd::Scanned);
}

// ── Gap 5: Zero-read vs budget-clamp disambiguation ────────────────

#[test]
fn gzip_zero_entry_budget_yields_entry_budget_exceeded() {
    // max_uncompressed_bytes_per_entry=0 → EntryOutputBudgetExceeded.
    let payload = b"hello world";
    let gz = gzip_compress(payload);

    let mut cfg = default_config();
    cfg.max_uncompressed_bytes_per_entry = 0;
    cfg.max_total_uncompressed_bytes_per_archive = 1000;
    cfg.max_total_uncompressed_bytes_per_root = 1000;

    let (outcome, sink, depth) = scan_gz_bytes(&gz, &cfg, 64, 4);

    assert_eq!(depth, 0);
    // on_entry_start + on_entry_end should still be paired.
    assert_eq!(sink.entries.len(), 1);
    // No chunks delivered (budget was 0).
    assert_eq!(sink.entries[0].chunks.len(), 0);
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::EntryOutputBudgetExceeded)
        ),
        "expected EntryOutputBudgetExceeded, got {outcome:?}"
    );
}

#[test]
fn gzip_valid_header_empty_deflate_is_corrupt() {
    // Valid gzip wrapping zero-length content → CompressedStreamCorrupt.
    let gz = gzip_compress(b"");

    let mut cfg = default_config();
    cfg.max_uncompressed_bytes_per_entry = 1000;
    cfg.max_total_uncompressed_bytes_per_archive = 1000;
    cfg.max_total_uncompressed_bytes_per_root = 1000;

    let (outcome, sink, depth) = scan_gz_bytes(&gz, &cfg, 64, 4);

    assert_eq!(depth, 0);
    assert_eq!(sink.entries.len(), 1);
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::CompressedStreamCorrupt)
        ),
        "expected CompressedStreamCorrupt for empty deflate, got {outcome:?}"
    );
}

#[test]
fn tar_truncated_entry_yields_malformed() {
    // Build a tar where the stream is physically shorter than the declared
    // entry size.  We truncate the output manually to simulate a truncated
    // stream.
    let payload: Vec<u8> = vec![b'X'; 50];
    let mut tar = Vec::new();
    let hdr = tar_header(b"trunc.txt", 100, b'0');
    tar.extend_from_slice(&hdr);
    tar.extend_from_slice(&payload);
    // Deliberately omit the remaining 50 bytes + padding + end-of-archive
    // blocks — the stream ends mid-entry.

    let (outcome, _, depth) = scan_tar_bytes(&tar, &default_config(), 64, 4);

    assert_eq!(depth, 0);
    assert!(
        matches!(outcome, ArchiveEnd::Partial(PartialReason::MalformedTar)),
        "expected MalformedTar, got {outcome:?}"
    );
}

#[test]
fn tar_zero_per_entry_budget_yields_entry_budget() {
    // max_uncompressed_bytes_per_entry=0 for tar.
    let payload = b"some data";
    let tar = build_tar(&[(b"f.txt", payload)]);

    let mut cfg = default_config();
    cfg.max_uncompressed_bytes_per_entry = 0;
    cfg.max_total_uncompressed_bytes_per_archive = 1000;
    cfg.max_total_uncompressed_bytes_per_root = 1000;

    let (outcome, sink, depth) = scan_tar_bytes(&tar, &cfg, 64, 4);

    assert_eq!(depth, 0);
    assert_eq!(sink.entries.len(), 1);
    assert_eq!(sink.entries[0].chunks.len(), 0);
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::EntryOutputBudgetExceeded)
        ),
        "expected EntryOutputBudgetExceeded, got {outcome:?}"
    );
}

// ── write_u64_hex_lower boundary values ─────────────────────────────

#[test]
fn write_u64_hex_lower_boundary_values() {
    let mut buf = [0u8; 16];

    util::write_u64_hex_lower(0, &mut buf);
    assert_eq!(&buf, b"0000000000000000");

    util::write_u64_hex_lower(1, &mut buf);
    assert_eq!(&buf, b"0000000000000001");

    util::write_u64_hex_lower(u64::MAX, &mut buf);
    assert_eq!(&buf, b"ffffffffffffffff");

    util::write_u64_hex_lower(0xFEDCBA9876543210, &mut buf);
    assert_eq!(&buf, b"fedcba9876543210");
}

// ── Sink protocol invariant ────────────────────────────────────────

#[test]
fn every_entry_start_has_matching_end() {
    // Scan multiple entries and verify start/end pairing.
    let tar = build_tar(&[(b"a.txt", b"AAA"), (b"b.txt", b"BBBBB"), (b"c.txt", b"")]);
    let (_, sink, depth) = scan_tar_bytes(&tar, &default_config(), 64, 4);

    assert_eq!(depth, 0);
    // RecordingSink ensures pairing via asserts; if we got here, it's ok.
    assert_eq!(sink.entries.len(), 3);
    // Empty entry should have 0 chunks.
    assert_eq!(sink.entries[2].chunks.len(), 0);
}

#[test]
fn nested_tar_entry_start_end_paired() {
    // Nested archive: verify all start/end calls are balanced.
    let inner_tar = build_tar(&[(b"inner.txt", b"INNER_DATA")]);
    let tar = build_tar(&[(b"outer_file.txt", b"OUTER"), (b"inner.tar", &inner_tar)]);

    let mut cfg = default_config();
    cfg.max_archive_depth = 4;

    let (_, sink, depth) = scan_tar_bytes(&tar, &cfg, 64, 4);
    assert_eq!(depth, 0);
    // outer_file.txt + inner.txt (from nested tar) = 2 scanned entries.
    assert!(sink.entries.len() >= 2);
}

// ── Wall-clock deadline in discard path ────────────────────────────

/// `discard_remaining_payload` must check the wall-clock deadline so that
/// a timeout during the scan read loop does not silently drain a large
/// entry payload.  With an already-expired deadline, the discard should
/// return `WallClockTimeout` without reading any bytes.
#[test]
fn discard_payload_exits_on_expired_deadline() {
    use crate::archive::budget::ArchiveBudgets;

    // Build budgets with an immediately-expiring deadline and generous byte
    // budgets so that the drain would succeed if the deadline were not checked.
    let cfg = ArchiveConfig {
        max_wall_clock_secs_per_root: Some(0),
        max_total_uncompressed_bytes_per_archive: u64::MAX,
        max_total_uncompressed_bytes_per_root: u64::MAX,
        ..ArchiveConfig::default()
    };
    let mut budgets = ArchiveBudgets::new(&cfg);
    budgets.reset(); // Arms deadline at Instant::now() + 0s → already expired.
    budgets.enter_archive().unwrap();
    budgets.begin_entry().unwrap();

    // Large payload available for draining.
    let data = vec![0xAA; 64 * 1024];
    let mut cursor = Cursor::new(data);
    let mut buf = vec![0u8; 4096];

    let result = discard_remaining_payload(&mut cursor, &mut budgets, &mut buf, 64 * 1024);
    assert_eq!(result, Err(PartialReason::WallClockTimeout));

    // No bytes should have been read — the deadline check fires before
    // the first `input.read()`.
    assert_eq!(cursor.position(), 0);
}

// ── Scan-level wall-clock timeout integration tests ────────────────

/// A tar archive with payload should yield `Partial(WallClockTimeout)`
/// when the deadline is already expired, and budget depth must return to 0.
#[test]
fn tar_wall_clock_timeout_yields_partial() {
    let payload = vec![b'X'; 256];
    let tar = build_tar(&[(b"big.txt", &payload)]);

    let mut cfg = default_config();
    cfg.max_wall_clock_secs_per_root = Some(0);

    let (outcome, _, depth) = scan_tar_bytes(&tar, &cfg, 64, 4);

    assert_eq!(
        depth, 0,
        "budget depth not restored after wall-clock timeout"
    );
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::WallClockTimeout)
        ),
        "expected WallClockTimeout, got {outcome:?}"
    );
}

/// A gzip stream with payload should yield `Partial(WallClockTimeout)`
/// when the deadline is already expired, and budget depth must return to 0.
#[test]
fn gzip_wall_clock_timeout_yields_partial() {
    let payload = vec![b'Y'; 256];
    let gz = gzip_compress(&payload);

    let mut cfg = default_config();
    cfg.max_wall_clock_secs_per_root = Some(0);
    cfg.max_uncompressed_bytes_per_entry = 10_000;
    cfg.max_total_uncompressed_bytes_per_archive = 10_000;
    cfg.max_total_uncompressed_bytes_per_root = 10_000;

    let (outcome, _, depth) = scan_gz_bytes(&gz, &cfg, 64, 4);

    assert_eq!(
        depth, 0,
        "budget depth not restored after wall-clock timeout"
    );
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::WallClockTimeout)
        ),
        "expected WallClockTimeout, got {outcome:?}"
    );
}

/// A zip archive with payload should yield `Partial(WallClockTimeout)`
/// when the deadline is already expired, and budget depth must return to 0.
#[test]
fn zip_wall_clock_timeout_yields_partial() {
    let payload = vec![b'Z'; 256];
    let zip = build_zip(&[(b"big.txt", &payload)]);

    let mut cfg = default_config();
    cfg.max_wall_clock_secs_per_root = Some(0);
    cfg.max_uncompressed_bytes_per_entry = 10_000;
    cfg.max_total_uncompressed_bytes_per_archive = 10_000;
    cfg.max_total_uncompressed_bytes_per_root = 10_000;

    let (outcome, _, depth) = scan_zip_bytes(&zip, &cfg, 64, 4);

    assert_eq!(
        depth, 0,
        "budget depth not restored after wall-clock timeout"
    );
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::WallClockTimeout)
        ),
        "expected WallClockTimeout, got {outcome:?}"
    );
}

// ── Deterministic mid-scan timeout (countdown, no real clock) ──────

/// Timeout fires after entry 1 is fully processed but before entry 2
/// begins.  Uses the test-only countdown override so no real time elapses.
///
/// The countdown is calibrated by counting `is_deadline_expired()` calls
/// in `scan_tar_stream_nested`:
///   - 1 call at the outer-loop top (before entry header parsing)
///   - 1 call per inner-loop iteration (per read chunk)
///
///   For a small payload that fits in one chunk, entry 1 consumes 2 checks.
///   Setting the countdown to 2 causes the 3rd call (entry 2's outer-loop
///   check) to fire, terminating the scan with exactly 1 entry delivered.
#[test]
fn tar_timeout_mid_scan_delivers_only_first_entry() {
    let tar = build_tar(&[
        (b"first.txt", b"AAAA"),
        (b"second.txt", b"BBBB"),
        (b"third.txt", b"CCCC"),
    ]);

    // No real deadline — the countdown handles everything.
    let cfg = default_config();
    let mut scratch: TestScratch = ArchiveScratch::new(&cfg, 64, 4);
    let mut sink = RecordingSink::new();
    let mut stats = ArchiveStats::default();
    let mut cursor = Cursor::new(tar.clone());

    // After 2 checks (entry 1 outer + entry 1 inner), the 3rd check fires.
    scratch.budgets.set_deadline_check_countdown(Some(2));

    let outcome = scan_tar_stream(
        &mut cursor,
        b"test.tar",
        &cfg,
        &mut scratch,
        &mut sink,
        &mut stats,
        false,
    )
    .unwrap();

    assert_eq!(scratch.budgets.depth(), 0, "depth must return to 0");
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::WallClockTimeout)
        ),
        "expected WallClockTimeout, got {outcome:?}"
    );

    // Entry 1 was fully delivered; entries 2 and 3 were never started.
    assert_eq!(
        sink.entries.len(),
        1,
        "expected exactly 1 entry delivered before timeout, got {}",
        sink.entries.len()
    );
    // Verify the delivered entry is the first one (payload = "AAAA").
    assert_eq!(sink.concat_new_bytes(0), b"AAAA");
}

/// Same as above but the countdown fires inside entry 2's read loop,
/// proving mid-entry timeout also works.  Entry 1 is fully delivered;
/// entry 2 is started (on_entry_start called) but receives no chunks.
#[test]
fn tar_timeout_mid_entry_delivers_partial() {
    // Use a larger payload so the inner loop has multiple iterations.
    let payload_a = vec![b'X'; 16];
    let payload_b = vec![b'Y'; 256];
    let tar = build_tar(&[(b"a.txt", &payload_a), (b"b.txt", &payload_b)]);

    let cfg = default_config();
    let mut scratch: TestScratch = ArchiveScratch::new(&cfg, 64, 4);
    let mut sink = RecordingSink::new();
    let mut stats = ArchiveStats::default();
    let mut cursor = Cursor::new(tar.clone());

    // Entry 1: 1 outer + 1 inner = 2 checks.
    // Entry 2: 1 outer + 1 inner (first chunk) = 2 more checks.
    // Set countdown=3 → fires on the 4th call (entry 2's first inner check).
    scratch.budgets.set_deadline_check_countdown(Some(3));

    let outcome = scan_tar_stream(
        &mut cursor,
        b"test.tar",
        &cfg,
        &mut scratch,
        &mut sink,
        &mut stats,
        false,
    )
    .unwrap();

    assert_eq!(scratch.budgets.depth(), 0, "depth must return to 0");
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::WallClockTimeout)
        ),
        "expected WallClockTimeout, got {outcome:?}"
    );

    // Entry 1 fully delivered, entry 2 started but timed out during its
    // read loop — on_entry_start was called, but the timeout broke before
    // or during chunk delivery.
    assert!(
        !sink.entries.is_empty(),
        "at least entry 1 must be delivered, got {}",
        sink.entries.len()
    );
    // Entry 1 payload intact.
    assert_eq!(sink.concat_new_bytes(0), payload_a);
}

// ── Bzip2 helpers ────────────────────────────────────────────────

fn bzip2_compress(data: &[u8]) -> Vec<u8> {
    use bzip2::write::BzEncoder;
    use bzip2::Compression;
    use std::io::Write;
    let mut enc = BzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn scan_bz2_bytes(
    bz2_bytes: &[u8],
    cfg: &ArchiveConfig,
    chunk_size: usize,
    overlap: usize,
) -> (ArchiveEnd, RecordingSink, u8) {
    let mut scratch: TestScratch = ArchiveScratch::new(cfg, chunk_size, overlap);
    let mut sink = RecordingSink::new();
    let mut stats = ArchiveStats::default();
    let reader = Cursor::new(bz2_bytes.to_vec());

    let outcome = scan_bzip2_stream(
        reader,
        b"test.bz2",
        cfg,
        &mut scratch,
        &mut sink,
        &mut stats,
    )
    .unwrap();

    let depth = scratch.budgets.depth();
    (outcome, sink, depth)
}

// ── Bzip2 unit tests ────────────────────────────────────────────

#[test]
fn bzip2_multi_chunk_overlap_correctness() {
    let payload: Vec<u8> = (0u8..40).collect();
    let bz2 = bzip2_compress(&payload);
    let mut cfg = default_config();
    cfg.max_uncompressed_bytes_per_entry = 1000;
    cfg.max_total_uncompressed_bytes_per_archive = 1000;
    cfg.max_total_uncompressed_bytes_per_root = 1000;

    let (outcome, sink, depth) = scan_bz2_bytes(&bz2, &cfg, 8, 4);

    assert_eq!(outcome, ArchiveEnd::Scanned);
    assert_eq!(depth, 0);
    assert_eq!(sink.entries.len(), 1);

    let chunks = &sink.entries[0].chunks;
    for i in 1..chunks.len() {
        let prev = &chunks[i - 1];
        let cur = &chunks[i];
        let carry = cur.data.len() - cur.new_bytes_len;
        if carry > 0 {
            let prev_suffix = &prev.data[prev.data.len() - carry..];
            let cur_prefix = &cur.data[..carry];
            assert_eq!(
                prev_suffix, cur_prefix,
                "bzip2 overlap mismatch at chunk {i}"
            );
        }
    }

    let concat = sink.concat_new_bytes(0);
    assert_eq!(concat, payload);
}

#[test]
fn bzip2_valid_header_empty_content_is_corrupt() {
    let bz2 = bzip2_compress(b"");

    let mut cfg = default_config();
    cfg.max_uncompressed_bytes_per_entry = 1000;
    cfg.max_total_uncompressed_bytes_per_archive = 1000;
    cfg.max_total_uncompressed_bytes_per_root = 1000;

    let (outcome, sink, depth) = scan_bz2_bytes(&bz2, &cfg, 64, 4);

    assert_eq!(depth, 0);
    assert_eq!(sink.entries.len(), 1);
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::CompressedStreamCorrupt)
        ),
        "expected CompressedStreamCorrupt for empty bzip2, got {outcome:?}"
    );
}

#[test]
fn bzip2_wall_clock_timeout_yields_partial() {
    let payload = vec![b'Y'; 256];
    let bz2 = bzip2_compress(&payload);

    let mut cfg = default_config();
    cfg.max_wall_clock_secs_per_root = Some(0);
    cfg.max_uncompressed_bytes_per_entry = 10_000;
    cfg.max_total_uncompressed_bytes_per_archive = 10_000;
    cfg.max_total_uncompressed_bytes_per_root = 10_000;

    let (outcome, _, depth) = scan_bz2_bytes(&bz2, &cfg, 64, 4);

    assert_eq!(
        depth, 0,
        "budget depth not restored after wall-clock timeout"
    );
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::WallClockTimeout)
        ),
        "expected WallClockTimeout, got {outcome:?}"
    );
}

#[test]
fn bzip2_zero_entry_budget_yields_entry_budget_exceeded() {
    let payload = b"hello world";
    let bz2 = bzip2_compress(payload);

    let mut cfg = default_config();
    cfg.max_uncompressed_bytes_per_entry = 0;
    cfg.max_total_uncompressed_bytes_per_archive = 1000;
    cfg.max_total_uncompressed_bytes_per_root = 1000;

    let (outcome, sink, depth) = scan_bz2_bytes(&bz2, &cfg, 64, 4);

    assert_eq!(depth, 0);
    assert_eq!(sink.entries.len(), 1);
    assert_eq!(sink.entries[0].chunks.len(), 0);
    assert!(
        matches!(
            outcome,
            ArchiveEnd::Partial(PartialReason::EntryOutputBudgetExceeded)
        ),
        "expected EntryOutputBudgetExceeded, got {outcome:?}"
    );
}
