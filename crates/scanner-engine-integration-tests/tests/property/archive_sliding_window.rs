//! Property tests for sliding-window overlap correctness in archive scanning.
//!
//! # Properties verified
//! P1: concat(new_bytes from all chunks) == original payload (up to budget).
//! P2: chunk[i].data[..carry] == chunk[i-1].data[prev_len-carry..] (overlap correctness).
//! P3: new_bytes_start[i] == new_bytes_start[i-1] + new_bytes_len[i-1] (monotonic).

use std::io::Cursor;

use proptest::prelude::*;
use scanner_scheduler::archive::{
    ArchiveConfig, ArchiveEnd, ArchiveEntrySink, ArchiveScratch, ArchiveStats, EntryChunk,
    EntryMeta, scan_tar_stream,
};

// ── RecordingSink (duplicated from scan.rs unit tests for property scope) ──

#[derive(Debug, Clone)]
struct RecordedChunk {
    data: Vec<u8>,
    new_bytes_start: u64,
    new_bytes_len: usize,
}

#[derive(Debug, Clone)]
struct RecordedEntry {
    chunks: Vec<RecordedChunk>,
}

#[derive(Debug, Default)]
struct RecordingSink {
    entries: Vec<RecordedEntry>,
    current: Option<RecordedEntry>,
}

impl ArchiveEntrySink for RecordingSink {
    type Error = std::convert::Infallible;

    fn on_entry_start(&mut self, _meta: &EntryMeta<'_>) -> Result<(), Self::Error> {
        assert!(self.current.is_none());
        self.current = Some(RecordedEntry { chunks: Vec::new() });
        Ok(())
    }

    fn on_entry_chunk(&mut self, chunk: EntryChunk<'_>) -> Result<(), Self::Error> {
        self.current.as_mut().unwrap().chunks.push(RecordedChunk {
            data: chunk.data.to_vec(),
            new_bytes_start: chunk.new_bytes_start,
            new_bytes_len: chunk.new_bytes_len,
        });
        Ok(())
    }

    fn on_entry_end(&mut self) -> Result<(), Self::Error> {
        self.entries.push(self.current.take().unwrap());
        Ok(())
    }
}

// ── Tar helpers ──

const TAR_BLOCK: usize = 512;

fn tar_header(name: &[u8], size: u64, typeflag: u8) -> [u8; TAR_BLOCK] {
    let mut buf = [0u8; TAR_BLOCK];
    let name_len = name.len().min(100);
    buf[..name_len].copy_from_slice(&name[..name_len]);
    let mut size_field = [b'0'; 11];
    let mut v = size;
    for i in (0..11).rev() {
        size_field[i] = b'0' + ((v & 7) as u8);
        v >>= 3;
    }
    buf[124..135].copy_from_slice(&size_field);
    buf[135] = 0;
    buf[136..148].copy_from_slice(b"00000000000\0");
    for b in &mut buf[148..156] {
        *b = b' ';
    }
    buf[156] = typeflag;
    buf[257..263].copy_from_slice(b"ustar\0");
    buf[263..265].copy_from_slice(b"00");
    let sum: u32 = buf.iter().map(|&b| b as u32).sum();
    let chk = format!("{:06o}\0 ", sum);
    buf[148..156].copy_from_slice(chk.as_bytes());
    buf
}

fn tar_pad(size: usize) -> usize {
    let rem = size % TAR_BLOCK;
    if rem == 0 { 0 } else { TAR_BLOCK - rem }
}

fn build_tar_single(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let hdr = tar_header(b"f.txt", payload.len() as u64, b'0');
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    out.extend_from_slice(&vec![0u8; tar_pad(payload.len())]);
    out.extend_from_slice(&[0u8; TAR_BLOCK * 2]);
    out
}

type TestScratch = ArchiveScratch<Cursor<Vec<u8>>>;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// P1 + P2 + P3: sliding-window overlap, concatenation, and monotonicity.
    #[test]
    fn tar_sliding_window_properties(
        payload in proptest::collection::vec(any::<u8>(), 1..2048),
        chunk_size in 4usize..128,
        overlap in 0usize..64,
    ) {
        let overlap = overlap.min(chunk_size);
        let tar = build_tar_single(&payload);

        let cfg = ArchiveConfig {
            enabled: true,
            max_uncompressed_bytes_per_entry: payload.len() as u64 + 1,
            max_total_uncompressed_bytes_per_archive: payload.len() as u64 + 1,
            max_total_uncompressed_bytes_per_root: payload.len() as u64 + 1,
            ..ArchiveConfig::default()
        };

        let mut scratch: TestScratch = ArchiveScratch::new(&cfg, chunk_size, overlap);
        let mut sink = RecordingSink::default();
        let mut stats = ArchiveStats::default();
        let mut cursor = Cursor::new(tar);

        let outcome = scan_tar_stream(
            &mut cursor, b"test.tar", &cfg, &mut scratch, &mut sink, &mut stats, false,
        ).unwrap();

        prop_assert_eq!(outcome, ArchiveEnd::Scanned);
        prop_assert_eq!(sink.entries.len(), 1);

        let chunks = &sink.entries[0].chunks;
        prop_assert!(!chunks.is_empty());

        // P1: concat(new_bytes) == payload.
        let mut concat = Vec::new();
        for c in chunks {
            let start = c.data.len() - c.new_bytes_len;
            concat.extend_from_slice(&c.data[start..]);
        }
        prop_assert_eq!(&concat, &payload);

        // P2: overlap correctness between consecutive chunks.
        for i in 1..chunks.len() {
            let prev = &chunks[i - 1];
            let cur = &chunks[i];
            let carry = cur.data.len() - cur.new_bytes_len;
            if carry > 0 {
                let prev_suffix = &prev.data[prev.data.len() - carry..];
                let cur_prefix = &cur.data[..carry];
                prop_assert_eq!(prev_suffix, cur_prefix,
                    "overlap mismatch at chunk {}", i);
            }
        }

        // P3: new_bytes_start is monotonically increasing.
        for i in 1..chunks.len() {
            let expected = chunks[i - 1].new_bytes_start + chunks[i - 1].new_bytes_len as u64;
            prop_assert_eq!(chunks[i].new_bytes_start, expected,
                "new_bytes_start not monotonic at chunk {}", i);
        }
    }

    /// Budget-clamped version: concat(new_bytes) == payload[..budget].
    #[test]
    fn tar_sliding_window_budget_clamp(
        payload in proptest::collection::vec(any::<u8>(), 32..1024),
        chunk_size in 4usize..64,
        overlap in 0usize..32,
        budget_frac in 0.1f64..0.9,
    ) {
        let overlap = overlap.min(chunk_size);
        let budget = ((payload.len() as f64 * budget_frac) as u64).max(1);
        let tar = build_tar_single(&payload);

        let cfg = ArchiveConfig {
            enabled: true,
            max_uncompressed_bytes_per_entry: budget,
            max_total_uncompressed_bytes_per_archive: budget + 1000,
            max_total_uncompressed_bytes_per_root: budget + 1000,
            ..ArchiveConfig::default()
        };

        let mut scratch: TestScratch = ArchiveScratch::new(&cfg, chunk_size, overlap);
        let mut sink = RecordingSink::default();
        let mut stats = ArchiveStats::default();
        let mut cursor = Cursor::new(tar);

        let _outcome = scan_tar_stream(
            &mut cursor, b"test.tar", &cfg, &mut scratch, &mut sink, &mut stats, false,
        ).unwrap();

        prop_assert_eq!(sink.entries.len(), 1);

        let chunks = &sink.entries[0].chunks;
        let mut concat = Vec::new();
        for c in chunks {
            let start = c.data.len() - c.new_bytes_len;
            concat.extend_from_slice(&c.data[start..]);
        }

        // Concatenated new_bytes == payload[..budget].
        prop_assert_eq!(concat.len() as u64, budget);
        prop_assert_eq!(&concat, &payload[..budget as usize]);

        // P2 + P3 still hold.
        for i in 1..chunks.len() {
            let prev = &chunks[i - 1];
            let cur = &chunks[i];
            let carry = cur.data.len() - cur.new_bytes_len;
            if carry > 0 {
                let prev_suffix = &prev.data[prev.data.len() - carry..];
                let cur_prefix = &cur.data[..carry];
                prop_assert_eq!(prev_suffix, cur_prefix);
            }
            let expected = chunks[i - 1].new_bytes_start + chunks[i - 1].new_bytes_len as u64;
            prop_assert_eq!(chunks[i].new_bytes_start, expected);
        }
    }
}
