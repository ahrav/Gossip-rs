//! bzip2 sniff helpers + streaming decoder wrapper.
//!
//! # Invariants
//! - The stream is read sequentially; no seeking.
//! - `MultiBzDecoder` treats concatenated members as a single stream.
//! - Compressed-byte accounting is sourced from [`CountedRead`].
//!
//! # Design Notes
//! - bzip2 streams do not carry a standard original-filename field, so callers
//!   synthesize display names (for example `<bunzip2>`) at attribution time.

use std::io::{self, Read};

use bzip2::read::MultiBzDecoder;

use crate::archive::util::CountedRead;

/// bzip2 magic prefix: ASCII `BZh`.
pub const BZIP2_MAGIC: [u8; 3] = [0x42, 0x5A, 0x68];

#[inline(always)]
pub fn is_bzip2_magic(header: &[u8]) -> bool {
    header.len() >= 4
        && header[0] == BZIP2_MAGIC[0]
        && header[1] == BZIP2_MAGIC[1]
        && header[2] == BZIP2_MAGIC[2]
        && header[3] >= b'1'
        && header[3] <= b'9'
}

/// Streaming bzip2 decoder with compressed-byte delta reporting.
///
/// Uses `MultiBzDecoder` to transparently decode concatenated bzip2 members
/// as a single stream, matching `GzipStream`'s use of `MultiGzDecoder`.
pub struct Bzip2Stream<R: Read> {
    dec: MultiBzDecoder<CountedRead<R>>,
    last_bytes: u64,
}

impl<R: Read> Bzip2Stream<R> {
    #[inline]
    pub fn new(reader: R) -> Self {
        Self {
            dec: MultiBzDecoder::new(CountedRead::new(reader)),
            last_bytes: 0,
        }
    }

    /// Read decompressed bytes.
    #[inline]
    pub fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.dec.read(dst)
    }

    /// Returns compressed bytes consumed since the previous call.
    ///
    /// This mirrors [`crate::archive::formats::GzipStream::take_compressed_delta`]
    /// so budget-charging code can stay codec-agnostic.
    #[inline]
    pub fn take_compressed_delta(&mut self) -> u64 {
        let now = self.dec.get_ref().bytes();
        let delta = now.saturating_sub(self.last_bytes);
        self.last_bytes = now;
        delta
    }

    #[inline]
    pub fn total_compressed(&self) -> u64 {
        self.dec.get_ref().bytes()
    }

    #[inline]
    pub fn into_inner(self) -> R {
        self.dec.into_inner().into_inner()
    }
}

impl<R: Read> Read for Bzip2Stream<R> {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.dec.read(dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_bzip2_magic() {
        assert!(is_bzip2_magic(b"BZh9"));
        assert!(!is_bzip2_magic(b"BZ"));
        assert!(!is_bzip2_magic(b"PK\x03\x04"));
    }

    /// 4-byte check: `"BZh"` alone is insufficient — the block-size digit
    /// (`'1'`–`'9'`) is required.
    #[test]
    fn magic_requires_block_size_digit() {
        assert!(!is_bzip2_magic(b"BZh"));
        assert!(is_bzip2_magic(b"BZh1"));
        assert!(is_bzip2_magic(b"BZh9"));
        assert!(!is_bzip2_magic(b"BZh0"));
        assert!(!is_bzip2_magic(b"BZha"));
    }

    /// Compress → decompress via `Bzip2Stream`, verify byte-exact round-trip.
    #[test]
    fn read_round_trip() {
        use bzip2::write::BzEncoder;
        use bzip2::Compression;
        use std::io::Write;

        let original = b"deterministic round-trip payload 0123456789";
        let mut enc = BzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(original).unwrap();
        let compressed = enc.finish().unwrap();

        let mut stream = Bzip2Stream::new(std::io::Cursor::new(&compressed));
        let mut output = Vec::new();
        let mut buf = [0u8; 16];
        loop {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            output.extend_from_slice(&buf[..n]);
        }
        assert_eq!(output, original);
    }

    /// Read in 16-byte chunks, accumulating deltas; the sum must equal
    /// `total_compressed()` which must equal the compressed input length.
    #[test]
    fn take_compressed_delta_accounting() {
        use bzip2::write::BzEncoder;
        use bzip2::Compression;
        use std::io::Write;

        let original: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let mut enc = BzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(&original).unwrap();
        let compressed = enc.finish().unwrap();
        let compressed_len = compressed.len() as u64;

        let mut stream = Bzip2Stream::new(std::io::Cursor::new(compressed));
        let mut buf = [0u8; 16];
        let mut delta_sum: u64 = 0;
        loop {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            delta_sum += stream.take_compressed_delta();
        }
        // Final delta after EOF read.
        delta_sum += stream.take_compressed_delta();

        assert_eq!(delta_sum, compressed_len);
        assert_eq!(stream.total_compressed(), compressed_len);
    }

    /// After EOF, `into_inner` recovers the underlying reader at its final
    /// position (all compressed bytes consumed).
    #[test]
    fn into_inner_recovers_reader() {
        use bzip2::write::BzEncoder;
        use bzip2::Compression;
        use std::io::Write;

        let original = b"recover inner reader";
        let mut enc = BzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(original).unwrap();
        let compressed = enc.finish().unwrap();
        let compressed_len = compressed.len() as u64;

        let mut stream = Bzip2Stream::new(std::io::Cursor::new(compressed));
        let mut buf = [0u8; 64];
        while stream.read(&mut buf).unwrap() > 0 {}

        let cursor = stream.into_inner();
        assert_eq!(cursor.position(), compressed_len);
    }

    #[test]
    fn decodes_all_concatenated_members() {
        use bzip2::write::BzEncoder;
        use bzip2::Compression;
        use std::io::Write;

        // Create two independently-compressed bzip2 members and concatenate them.
        let part_a = b"FIRST_MEMBER_DATA_AAA";
        let part_b = b"SECOND_MEMBER_DATA_BBB";

        let mut compressed = Vec::new();
        {
            let mut enc = BzEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(part_a).unwrap();
            compressed.extend(enc.finish().unwrap());
        }
        {
            let mut enc = BzEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(part_b).unwrap();
            compressed.extend(enc.finish().unwrap());
        }

        // Decode through Bzip2Stream — should yield both members.
        let mut stream = Bzip2Stream::new(std::io::Cursor::new(&compressed));
        let mut output = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            output.extend_from_slice(&buf[..n]);
        }

        let expected_len = part_a.len() + part_b.len();
        assert_eq!(
            output.len(),
            expected_len,
            "expected {expected_len} decompressed bytes but got {}; \
             only the first member was decoded",
            output.len()
        );
        assert_eq!(&output[..part_a.len()], part_a.as_slice());
        assert_eq!(&output[part_a.len()..], part_b.as_slice());
    }
}
