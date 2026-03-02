//! gzip sniff helpers + streaming decoder wrapper.
//!
//! # Invariants
//! - The stream is read sequentially; no seeking.
//! - `MultiGzDecoder` treats concatenated members as a single stream.
//!
//! # Design Notes
//! - [`CountedRead`](crate::archive::util::CountedRead) provides compressed-byte accounting for ratio budgets.
//! - `flate2::read::MultiGzDecoder` may allocate internally; this is treated as
//!   an allowed library exception under the "no allocations after startup"
//!   policy.
//! - Header filename parsing is bounded by a caller-provided scratch buffer;
//!   if the name is missing or exceeds caps, callers should fall back to
//!   `<gunzip>` for virtual path attribution.

use std::io::{self, Read};

use flate2::read::MultiGzDecoder;

use crate::archive::util::CountedRead;

/// gzip magic bytes (RFC 1952).
pub const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const GZIP_CM_DEFLATE: u8 = 8;
const GZIP_FLAG_FEXTRA: u8 = 0x04;
const GZIP_FLAG_FNAME: u8 = 0x08;

#[inline(always)]
pub fn is_gzip_magic(header: &[u8]) -> bool {
    header.len() >= 2 && header[0] == GZIP_MAGIC[0] && header[1] == GZIP_MAGIC[1]
}

/// Reader that can "peek" a bounded prefix without losing it.
///
/// This is used to parse the gzip header (for the optional original filename)
/// while still feeding the exact bytes to the decoder.
pub(crate) struct PeekRead<R: Read> {
    inner: R,
    buf: Vec<u8>,
    filled: usize,
    pos: usize,
}

impl<R: Read> PeekRead<R> {
    #[inline]
    pub fn new(inner: R, buf: Vec<u8>) -> Self {
        Self {
            inner,
            buf,
            filled: 0,
            pos: 0,
        }
    }

    /// Fill the peek buffer up to `buf.len()` (bounded).
    #[inline]
    pub fn prefill(&mut self) -> io::Result<usize> {
        let cap = self.buf.len();
        while self.filled < cap {
            let n = self.inner.read(&mut self.buf[self.filled..cap])?;
            if n == 0 {
                break;
            }
            self.filled += n;
        }
        Ok(self.filled)
    }

    #[inline]
    pub fn peeked(&self) -> &[u8] {
        &self.buf[..self.filled]
    }

    /// Return the inner reader and the peek buffer for reuse by the caller.
    #[inline]
    pub fn into_parts(self) -> (R, Vec<u8>) {
        (self.inner, self.buf)
    }
}

impl<R: Read> Read for PeekRead<R> {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if self.pos < self.filled {
            let n = (self.filled - self.pos).min(dst.len());
            dst[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(dst)
    }
}

/// Streaming gzip decoder that supports concatenated members.
///
/// Internally uses `flate2::read::MultiGzDecoder`.
///
/// # Guarantees
/// - `take_compressed_delta()` reports bytes consumed since the last call.
/// - `read()` yields decompressed bytes or an error on corruption.
pub struct GzipStream<R: Read> {
    dec: MultiGzDecoder<CountedRead<R>>,
    last_bytes: u64,
}

impl<R: Read> GzipStream<R> {
    #[inline]
    pub fn new(reader: R) -> Self {
        Self {
            dec: MultiGzDecoder::new(CountedRead::new(reader)),
            last_bytes: 0,
        }
    }

    /// Construct a gzip stream while extracting the optional header filename.
    ///
    /// `header_buf` is a preallocated scratch buffer used for prefix peeking.
    /// `name_buf` is filled with the raw filename bytes when present and
    /// within `max_name_len`. If parsing fails or exceeds bounds, it remains
    /// empty and `<gunzip>` should be used instead.
    ///
    /// `header_buf` is moved into the returned stream's internal peek buffer.
    /// To reuse it, call `GzipStream::into_inner()` and then
    /// `PeekRead::into_parts()` on the returned reader.
    ///
    /// Returns `Some(len)` when a valid FNAME was parsed and copied into
    /// `name_buf`; otherwise returns `None`.
    pub(crate) fn new_with_header(
        reader: R,
        header_buf: &mut Vec<u8>,
        name_buf: &mut Vec<u8>,
        max_name_len: usize,
    ) -> io::Result<(GzipStream<PeekRead<R>>, Option<usize>)> {
        let buf = std::mem::take(header_buf);
        let mut peek = PeekRead::new(reader, buf);
        let filled = match peek.prefill() {
            Ok(n) => n,
            Err(e) => {
                let (_r, buf) = peek.into_parts();
                *header_buf = buf;
                return Err(e);
            }
        };
        if filled == 0 {
            let (_r, buf) = peek.into_parts();
            *header_buf = buf;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "gzip header truncated",
            ));
        }
        let name_len = parse_gzip_name(peek.peeked(), name_buf, max_name_len);
        Ok((GzipStream::new(peek), name_len))
    }

    /// Read decompressed bytes.
    #[inline]
    pub fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.dec.read(dst)
    }

    /// Returns the delta of compressed bytes consumed since last call.
    ///
    /// Call this after `read()` to charge budgets.
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

impl<R: Read> Read for GzipStream<R> {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        self.dec.read(dst)
    }
}

// Best-effort parse of gzip FNAME from a bounded prefix.
fn parse_gzip_name(prefix: &[u8], name_buf: &mut Vec<u8>, max_name_len: usize) -> Option<usize> {
    name_buf.clear();

    if prefix.len() < 10 {
        return None;
    }
    if prefix[0] != GZIP_MAGIC[0] || prefix[1] != GZIP_MAGIC[1] {
        return None;
    }
    if prefix[2] != GZIP_CM_DEFLATE {
        return None;
    }

    let flg = prefix[3];
    let mut idx = 10usize;

    if (flg & GZIP_FLAG_FEXTRA) != 0 {
        if idx + 2 > prefix.len() {
            return None;
        }
        let xlen = u16::from_le_bytes([prefix[idx], prefix[idx + 1]]) as usize;
        idx += 2;
        if idx + xlen > prefix.len() {
            return None;
        }
        idx += xlen;
    }

    if (flg & GZIP_FLAG_FNAME) == 0 {
        return None;
    }

    let mut end = idx;
    while end < prefix.len() && prefix[end] != 0 {
        if end - idx >= max_name_len {
            return None;
        }
        end += 1;
    }
    if end >= prefix.len() {
        return None;
    }
    let name_len = end.saturating_sub(idx);
    if name_len == 0 {
        return None;
    }
    if name_len > name_buf.capacity() {
        return None;
    }

    name_buf.extend_from_slice(&prefix[idx..end]);
    Some(name_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_gzip_magic() {
        assert!(is_gzip_magic(&[0x1f, 0x8b, 0x08, 0x00]));
        assert!(!is_gzip_magic(&[0x1f]));
        assert!(!is_gzip_magic(&[0x50, 0x4b]));
    }

    // ── parse_gzip_name tests ───────────────────────────────────────────

    /// Build a minimal gzip header with the given flags, optional FEXTRA,
    /// and optional FNAME payload.  Returns the raw header bytes.
    fn build_header(flags: u8, fextra: Option<&[u8]>, fname: Option<&[u8]>) -> Vec<u8> {
        let mut buf = Vec::new();
        // Magic (2) + CM (1) + FLG (1) + MTIME (4) + XFL (1) + OS (1) = 10
        buf.extend_from_slice(&GZIP_MAGIC);
        buf.push(GZIP_CM_DEFLATE); // CM
        buf.push(flags); // FLG
        buf.extend_from_slice(&[0u8; 4]); // MTIME
        buf.push(0); // XFL
        buf.push(0xFF); // OS = unknown

        if let Some(extra) = fextra {
            let xlen = extra.len() as u16;
            buf.extend_from_slice(&xlen.to_le_bytes());
            buf.extend_from_slice(extra);
        }

        if let Some(name) = fname {
            buf.extend_from_slice(name);
            buf.push(0); // NUL terminator
        }

        buf
    }

    #[test]
    fn parse_fname_without_fextra() {
        let header = build_header(GZIP_FLAG_FNAME, None, Some(b"hello.txt"));
        let mut name_buf = Vec::with_capacity(256);
        let len = parse_gzip_name(&header, &mut name_buf, 256);
        assert_eq!(len, Some(9));
        assert_eq!(&name_buf, b"hello.txt");
    }

    #[test]
    fn parse_fname_with_fextra() {
        let flags = GZIP_FLAG_FNAME | GZIP_FLAG_FEXTRA;
        let extra = b"XX"; // 2-byte extra field payload
        let header = build_header(flags, Some(extra), Some(b"data.bin"));
        let mut name_buf = Vec::with_capacity(256);
        let len = parse_gzip_name(&header, &mut name_buf, 256);
        assert_eq!(len, Some(8));
        assert_eq!(&name_buf, b"data.bin");
    }

    #[test]
    fn parse_truncated_header() {
        let header = &[0x1f, 0x8b, 0x08]; // Only 3 bytes — too short
        let mut name_buf = Vec::with_capacity(256);
        assert_eq!(parse_gzip_name(header, &mut name_buf, 256), None);
    }

    #[test]
    fn parse_no_nul_terminator() {
        // FNAME flag set but name runs to end of buffer without NUL.
        let mut header = Vec::new();
        header.extend_from_slice(&GZIP_MAGIC);
        header.push(GZIP_CM_DEFLATE);
        header.push(GZIP_FLAG_FNAME);
        header.extend_from_slice(&[0u8; 6]); // MTIME + XFL + OS
        header.extend_from_slice(b"noterm"); // No NUL terminator
        let mut name_buf = Vec::with_capacity(256);
        assert_eq!(parse_gzip_name(&header, &mut name_buf, 256), None);
    }

    #[test]
    fn parse_name_exceeds_max_len() {
        let long_name = vec![b'a'; 100];
        let header = build_header(GZIP_FLAG_FNAME, None, Some(&long_name));
        let mut name_buf = Vec::with_capacity(256);
        // max_name_len = 50, but name is 100 bytes.
        assert_eq!(parse_gzip_name(&header, &mut name_buf, 50), None);
    }

    #[test]
    fn parse_empty_fname() {
        // FNAME flag set but name is zero-length (NUL immediately).
        let header = build_header(GZIP_FLAG_FNAME, None, Some(b""));
        let mut name_buf = Vec::with_capacity(256);
        assert_eq!(parse_gzip_name(&header, &mut name_buf, 256), None);
    }

    #[test]
    fn parse_wrong_compression_method() {
        let mut header = build_header(GZIP_FLAG_FNAME, None, Some(b"test.txt"));
        header[2] = 0x09; // Invalid CM (not deflate)
        let mut name_buf = Vec::with_capacity(256);
        assert_eq!(parse_gzip_name(&header, &mut name_buf, 256), None);
    }
}
