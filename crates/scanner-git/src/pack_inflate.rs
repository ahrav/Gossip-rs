//! Pack object decoding for tree loading.
//!
//! Provides bounded inflate helpers, pack header parsing, and delta
//! application needed to read tree objects from pack files.
//!
//! # Scope
//! - Parses pack headers and entry headers.
//! - Inflates zlib-compressed object data with strict size caps.
//! - Applies Git's delta encoding (OFS_DELTA and REF_DELTA).
//! - Does **not** verify pack checksums or object CRCs.
//!
//! # Caller Expectations
//! - Offsets passed to `entry_header_at` must point to entry headers
//!   (typically from MIDX/IDX offsets).
//! - Size caps must be enforced by the caller before allocating outputs.
//! - The pack trailer hash is ignored; integrity checks happen elsewhere.

use std::cell::RefCell;
use std::fmt;

use super::object_id::OidBytes;
use flate2::Decompress;

/// Pack header size: magic(4) + version(4) + object_count(4).
const PACK_HEADER_SIZE: usize = 12;

/// Maximum OFS encoding bytes (negative offset varint).
const MAX_OFS_BYTES: usize = 10; // ceil(64/7)

/// Internal inflate buffer size.
const INFLATE_BUF_SIZE: usize = 64 * 1024;

/// Combined per-thread inflate scratch state.
///
/// Merging `Decompress` and the scratch buffer into a single `thread_local!`
/// halves the TLS lookup and `RefCell::borrow_mut()` overhead (1 borrow
/// instead of 2).
struct InflateScratch {
    de: Decompress,
    buf: [u8; INFLATE_BUF_SIZE],
}

thread_local! {
    static INFLATE_SCRATCH: RefCell<InflateScratch> = RefCell::new(InflateScratch {
        de: Decompress::new(true),
        buf: [0u8; INFLATE_BUF_SIZE],
    });
}

/// Fill spare capacity with `0xDE` in debug builds so that any
/// uninitialized-read past the logical length hits a deterministic
/// poison pattern instead of whatever the allocator left behind.
/// No-op in release builds.
#[inline(always)]
fn poison_spare_capacity(buf: &mut Vec<u8>) {
    #[cfg(debug_assertions)]
    {
        for slot in buf.spare_capacity_mut() {
            slot.write(0xDE);
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = buf;
}

/// Runs an inflate operation using per-thread scratch buffers.
///
/// This avoids per-call allocations by reusing a thread-local `Decompress`
/// and output buffer.
///
/// # Panics
///
/// Panics if called reentrantly on the same thread (the `RefCell` borrow
/// guard detects double-borrow). Callers must not invoke inflate helpers
/// recursively from within an `inflate_stream` callback. The `_with`
/// variants that accept a caller-owned `Decompress` bypass this TLS
/// entirely and are safe for reentrant use.
fn with_inflate_scratch<F, R>(f: F) -> R
where
    F: FnOnce(&mut Decompress, &mut [u8]) -> R,
{
    INFLATE_SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        let s = &mut *scratch;
        f(&mut s.de, &mut s.buf)
    })
}

/// Parsed object kind for non-delta entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Commit,
    Tree,
    Blob,
    Tag,
}

/// Parsed pack entry kind from header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    /// Non-delta object (commit, tree, blob, tag).
    NonDelta { kind: ObjectKind },
    /// OFS_DELTA: base at backward offset in same pack.
    OfsDelta { base_offset: u64 },
    /// REF_DELTA: base identified by OID.
    RefDelta { base_oid: OidBytes },
}

/// Pack parse error taxonomy (covers both file header and entry header parsing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackParseError {
    TooSmall,
    BadSignature,
    UnsupportedVersion(u32),
    OffsetOutOfRange(u64),
    HeaderTooLong,
    Truncated,
    BadObjType(u8),
    BadOfsEncoding,
    OfsUnderflow,
    BadOidLen(usize),
}

impl fmt::Display for PackParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => write!(f, "pack too small"),
            Self::BadSignature => write!(f, "bad pack signature"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported pack version {v}"),
            Self::OffsetOutOfRange(o) => write!(f, "offset {o} out of range"),
            Self::HeaderTooLong => write!(f, "header exceeded safety bound"),
            Self::Truncated => write!(f, "truncated pack data"),
            Self::BadObjType(t) => write!(f, "bad object type {t}"),
            Self::BadOfsEncoding => write!(f, "bad OFS_DELTA encoding"),
            Self::OfsUnderflow => write!(f, "OFS_DELTA base underflow"),
            Self::BadOidLen(n) => write!(f, "invalid OID length {n}"),
        }
    }
}

impl std::error::Error for PackParseError {}

/// Inflate error taxonomy.
#[derive(Debug, PartialEq, Eq)]
pub enum InflateError {
    LimitExceeded,
    TruncatedInput,
    Stalled,
    Backend,
}

impl fmt::Display for InflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded => write!(f, "inflate limit exceeded"),
            Self::TruncatedInput => write!(f, "truncated input"),
            Self::Stalled => write!(f, "inflate stalled"),
            Self::Backend => write!(f, "inflate backend error"),
        }
    }
}

impl std::error::Error for InflateError {}

/// Delta apply error taxonomy.
#[derive(Debug, PartialEq, Eq)]
pub enum DeltaError {
    Truncated,
    VarintOverflow,
    BaseSizeMismatch,
    ResultSizeMismatch,
    BadCommandZero,
    CopyOutOfRange,
    OutputOverrun,
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "delta truncated"),
            Self::VarintOverflow => write!(f, "delta varint overflow"),
            Self::BaseSizeMismatch => write!(f, "delta base size mismatch"),
            Self::ResultSizeMismatch => write!(f, "delta result size mismatch"),
            Self::BadCommandZero => write!(f, "delta command zero"),
            Self::CopyOutOfRange => write!(f, "delta copy out of range"),
            Self::OutputOverrun => write!(f, "delta output overrun"),
        }
    }
}

impl std::error::Error for DeltaError {}

/// Errors from pack object decoding.
#[derive(Debug)]
pub enum PackObjectError {
    PackParse(PackParseError),
    Inflate(InflateError),
    Delta(DeltaError),
}

impl fmt::Display for PackObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackParse(err) => write!(f, "{err}"),
            Self::Inflate(err) => write!(f, "{err}"),
            Self::Delta(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PackObjectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PackParse(err) => Some(err),
            Self::Inflate(err) => Some(err),
            Self::Delta(err) => Some(err),
        }
    }
}

impl From<PackParseError> for PackObjectError {
    fn from(err: PackParseError) -> Self {
        Self::PackParse(err)
    }
}

impl From<InflateError> for PackObjectError {
    fn from(err: InflateError) -> Self {
        Self::Inflate(err)
    }
}

impl From<DeltaError> for PackObjectError {
    fn from(err: DeltaError) -> Self {
        Self::Delta(err)
    }
}

/// Entry header parsed from a pack file.
///
/// The `data_start` offset points to the beginning of the zlib stream
/// within the pack. The header itself is variable length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryHeader {
    /// Uncompressed payload size (delta entries store delta bytes, not the result).
    pub size: u64,
    /// Byte offset where the zlib stream begins.
    pub data_start: usize,
    /// Entry kind (non-delta or delta with base reference).
    pub kind: EntryKind,
}

/// Zero-copy view over pack file bytes.
///
/// The trailing hash (20 or 32 bytes) is excluded from `data_end` to prevent
/// misparsing the checksum as object data. No checksum verification is done.
#[derive(Debug)]
pub struct PackFile<'a> {
    bytes: &'a [u8],
    oid_len: usize,
    data_end: usize,
}

/// Cached pack header metadata for repeated entry parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackHeader {
    oid_len: usize,
    data_end: usize,
}

impl<'a> PackFile<'a> {
    /// Parse and validate a pack file header.
    ///
    /// Expects the full pack bytes including the trailing hash.
    /// The trailing hash is excluded from `data_end` to prevent misparsing.
    pub fn parse(bytes: &'a [u8], oid_len: usize) -> Result<Self, PackParseError> {
        let header = Self::parse_header(bytes, oid_len)?;
        Ok(Self::from_header(bytes, header))
    }

    /// Parse and validate a pack file header for caching.
    pub fn parse_header(bytes: &[u8], oid_len: usize) -> Result<PackHeader, PackParseError> {
        if oid_len != 20 && oid_len != 32 {
            return Err(PackParseError::BadOidLen(oid_len));
        }

        let min_size = PACK_HEADER_SIZE + oid_len;
        if bytes.len() < min_size {
            return Err(PackParseError::TooSmall);
        }
        if &bytes[0..4] != b"PACK" {
            return Err(PackParseError::BadSignature);
        }
        let ver = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if ver != 2 && ver != 3 {
            return Err(PackParseError::UnsupportedVersion(ver));
        }

        let data_end = bytes.len() - oid_len;
        debug_assert!(data_end >= PACK_HEADER_SIZE);

        Ok(PackHeader { oid_len, data_end })
    }

    /// Construct a pack view from cached header metadata.
    pub fn from_header(bytes: &'a [u8], header: PackHeader) -> Self {
        Self {
            bytes,
            oid_len: header.oid_len,
            data_end: header.data_end,
        }
    }

    /// Parse the entry header at `offset`.
    ///
    /// `max_header_bytes` is a safety bound to prevent runaway parsing on
    /// corrupt data. For delta entries, the returned `data_start` points
    /// after the base reference (OFS encoding or REF OID) so callers can
    /// immediately begin inflating the delta payload.
    pub fn entry_header_at(
        &self,
        offset: u64,
        max_header_bytes: usize,
    ) -> Result<EntryHeader, PackParseError> {
        let mut pos = offset as usize;
        if pos < PACK_HEADER_SIZE || pos >= self.data_end {
            return Err(PackParseError::OffsetOutOfRange(offset));
        }

        let start = pos;

        let first = self.byte_at(pos)?;
        pos += 1;

        let obj_type = (first >> 4) & 0x07;
        let mut size: u64 = (first & 0x0f) as u64;
        let mut shift: u32 = 4;

        let mut byte = first;
        while (byte & 0x80) != 0 {
            if pos - start >= max_header_bytes {
                return Err(PackParseError::HeaderTooLong);
            }
            byte = self.byte_at(pos)?;
            pos += 1;
            size |= ((byte & 0x7f) as u64) << shift;
            shift = shift.saturating_add(7);
            if shift > 63 {
                return Err(PackParseError::HeaderTooLong);
            }
        }

        let kind = match obj_type {
            1 => EntryKind::NonDelta {
                kind: ObjectKind::Commit,
            },
            2 => EntryKind::NonDelta {
                kind: ObjectKind::Tree,
            },
            3 => EntryKind::NonDelta {
                kind: ObjectKind::Blob,
            },
            4 => EntryKind::NonDelta {
                kind: ObjectKind::Tag,
            },
            6 => {
                let (base_offset, new_pos) =
                    self.parse_ofs_base(offset, pos, start, max_header_bytes)?;
                pos = new_pos;
                EntryKind::OfsDelta { base_offset }
            }
            7 => {
                let end = pos + self.oid_len;
                if end > self.data_end {
                    return Err(PackParseError::Truncated);
                }
                let base_oid = OidBytes::try_from_slice(&self.bytes[pos..end])
                    .ok_or(PackParseError::BadOidLen(self.oid_len))?;
                pos = end;
                EntryKind::RefDelta { base_oid }
            }
            x => return Err(PackParseError::BadObjType(x)),
        };

        Ok(EntryHeader {
            size,
            data_start: pos,
            kind,
        })
    }

    /// Raw bytes from `start` to end of data region.
    ///
    /// The returned slice excludes the trailing pack hash.
    #[inline]
    pub fn slice_from(&self, start: usize) -> &'a [u8] {
        debug_assert!(start <= self.data_end, "slice_from out of range");
        &self.bytes[start..self.data_end]
    }

    #[inline]
    fn byte_at(&self, pos: usize) -> Result<u8, PackParseError> {
        self.bytes
            .get(pos)
            .copied()
            .ok_or(PackParseError::Truncated)
    }

    /// Parses OFS_DELTA base offset encoding.
    ///
    /// The encoding stores a negative offset as a variable-length base-128
    /// number with a continuation bit; see `gitformat-pack(5)`.
    fn parse_ofs_base(
        &self,
        delta_offset: u64,
        mut pos: usize,
        start: usize,
        max_header_bytes: usize,
    ) -> Result<(u64, usize), PackParseError> {
        let ofs_start = pos;
        let mut c = self.byte_at(pos)?;
        pos += 1;

        let mut val: u64 = (c & 0x7f) as u64;
        let mut bytes_read = 1usize;

        while (c & 0x80) != 0 {
            if bytes_read >= MAX_OFS_BYTES || pos - start >= max_header_bytes {
                return Err(PackParseError::HeaderTooLong);
            }
            c = self.byte_at(pos)?;
            pos += 1;
            bytes_read += 1;
            val = (val + 1) << 7;
            val |= (c & 0x7f) as u64;
        }

        if val >= delta_offset {
            return Err(PackParseError::OfsUnderflow);
        }

        let base_offset = delta_offset - val;
        Ok((base_offset, ofs_start + bytes_read))
    }
}

/// Inflate a zlib stream with a hard output cap, using a caller-provided
/// `Decompress`. The decompressor is reset before use.
///
/// Returns the number of input bytes consumed from `input`.
///
/// Decompressed bytes are written directly into `out`'s spare capacity,
/// avoiding an intermediate buffer copy.
///
/// On error, `out` may contain a partial prefix; callers should discard it.
pub fn inflate_limited_with(
    de: &mut Decompress,
    input: &[u8],
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<usize, InflateError> {
    use flate2::{FlushDecompress, Status};

    de.reset(true);
    out.clear();
    out.reserve(max_out);
    poison_spare_capacity(out);

    let mut in_pos: usize = 0;

    loop {
        let before_in = de.total_in() as usize;
        let before_out = de.total_out() as usize;

        // Decompress directly into Vec spare capacity, capped so
        // total output never exceeds max_out.
        let remaining = max_out
            .checked_sub(out.len())
            .ok_or(InflateError::LimitExceeded)?;
        let spare = out.spare_capacity_mut();
        let buf_len = spare.len().min(remaining);
        let out_buf = &mut spare[..buf_len];

        let status = de
            .decompress_uninit(&input[in_pos..], out_buf, FlushDecompress::None)
            .map_err(|_| InflateError::Backend)?;

        let consumed = de.total_in() as usize - before_in;
        let produced = de.total_out() as usize - before_out;
        in_pos += consumed;

        if produced != 0 {
            if produced > buf_len {
                return Err(InflateError::Backend);
            }
            let new_len = out
                .len()
                .checked_add(produced)
                .ok_or(InflateError::LimitExceeded)?;
            if new_len > out.capacity() {
                return Err(InflateError::Backend);
            }
            if new_len > max_out {
                return Err(InflateError::LimitExceeded);
            }
            // SAFETY:
            // 1. `decompress_uninit` wrote exactly `produced` initialized bytes
            //    into the passed spare-capacity slice.
            // 2. `new_len <= out.capacity()` and `new_len <= max_out` were
            //    checked above in release builds.
            // 3. `out` uniquely owns its allocation.
            unsafe { out.set_len(new_len) };
        }

        match status {
            Status::StreamEnd => return Ok(in_pos),
            Status::Ok => {
                if consumed == 0 && produced == 0 {
                    if in_pos >= input.len() {
                        return Err(InflateError::TruncatedInput);
                    }
                    return Err(InflateError::Stalled);
                }
                if out.len() >= max_out {
                    if in_pos >= input.len() {
                        return Err(InflateError::TruncatedInput);
                    }
                    return Err(InflateError::LimitExceeded);
                }
            }
            Status::BufError => {
                if in_pos >= input.len() {
                    return Err(InflateError::TruncatedInput);
                }
                if out.len() >= max_out {
                    return Err(InflateError::LimitExceeded);
                }
            }
        }
    }
}

/// Inflate a zlib stream with a hard output cap, using the thread-local
/// `Decompress`.
///
/// Convenience wrapper around [`inflate_limited_with`] for callers that
/// don't maintain their own decompressor.
pub fn inflate_limited(
    input: &[u8],
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<usize, InflateError> {
    with_inflate_scratch(|de, _buf| inflate_limited_with(de, input, out, max_out))
}

/// Inflate a zlib stream into a caller-provided sink with an exact output size.
///
/// Returns the number of input bytes consumed from `input`.
///
/// The sink is invoked with contiguous output chunks. The total output bytes
/// must equal `expected`, otherwise `TruncatedInput` is returned. Callers
/// should not assume any particular chunk size.
pub fn inflate_stream(
    input: &[u8],
    expected: usize,
    mut on_chunk: impl FnMut(&[u8]) -> Result<(), InflateError>,
) -> Result<usize, InflateError> {
    use flate2::{FlushDecompress, Status};

    with_inflate_scratch(|de, buf| {
        de.reset(true);
        let mut in_pos: usize = 0;
        let mut out_total: usize = 0;

        loop {
            let before_in = de.total_in() as usize;
            let before_out = de.total_out() as usize;

            let status = de
                .decompress(&input[in_pos..], buf, FlushDecompress::None)
                .map_err(|_| InflateError::Backend)?;

            let consumed = de.total_in() as usize - before_in;
            let produced = de.total_out() as usize - before_out;
            in_pos += consumed;

            if produced != 0 {
                let end = out_total
                    .checked_add(produced)
                    .ok_or(InflateError::LimitExceeded)?;
                if end > expected {
                    return Err(InflateError::LimitExceeded);
                }
                on_chunk(&buf[..produced])?;
                out_total = end;
            }

            match status {
                Status::StreamEnd => {
                    if out_total != expected {
                        return Err(InflateError::TruncatedInput);
                    }
                    return Ok(in_pos);
                }
                Status::Ok => {
                    if consumed == 0 && produced == 0 {
                        if in_pos >= input.len() {
                            return Err(InflateError::TruncatedInput);
                        }
                        return Err(InflateError::Stalled);
                    }
                }
                Status::BufError => {
                    if in_pos >= input.len() {
                        return Err(InflateError::TruncatedInput);
                    }
                }
            }
        }
    })
}

/// Inflate a zlib stream expecting exactly `expected` output bytes, using a
/// caller-provided `Decompress`.
pub fn inflate_exact_with(
    de: &mut Decompress,
    input: &[u8],
    out: &mut Vec<u8>,
    expected: usize,
) -> Result<usize, InflateError> {
    let consumed = inflate_limited_with(de, input, out, expected)?;
    if out.len() != expected {
        return Err(InflateError::TruncatedInput);
    }
    Ok(consumed)
}

/// Inflate a zlib stream expecting exactly `expected` output bytes.
///
/// Convenience wrapper around [`inflate_exact_with`] using the thread-local
/// `Decompress`.
pub fn inflate_exact(
    input: &[u8],
    out: &mut Vec<u8>,
    expected: usize,
) -> Result<usize, InflateError> {
    with_inflate_scratch(|de, _buf| inflate_exact_with(de, input, out, expected))
}

/// Reads a Git delta varint (LEB128-like) as u64.
///
/// Fails if the encoding would exceed 64 bits or is truncated.
fn read_leb128_u64(data: &[u8], pos: &mut usize) -> Result<u64, DeltaError> {
    let mut shift: u32 = 0;
    let mut result: u64 = 0;

    for _ in 0..10 {
        if *pos >= data.len() {
            return Err(DeltaError::Truncated);
        }
        let b = data[*pos];
        *pos += 1;

        result |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok(result);
        }
        shift = shift.saturating_add(7);
        if shift > 63 {
            return Err(DeltaError::VarintOverflow);
        }
    }
    Err(DeltaError::VarintOverflow)
}

/// Converts a decoded delta size to `usize` with a callsite-selected overflow error.
#[inline(always)]
fn delta_size_to_usize(value: u64, overflow_err: DeltaError) -> Result<usize, DeltaError> {
    usize::try_from(value).map_err(|_| overflow_err)
}

/// Parse the base and result sizes from a git delta buffer.
///
/// This only reads header varints; it does not validate the remainder.
/// Values that do not fit in `usize` fail with the caller-specific overflow
/// error (`BaseSizeMismatch` for base size, `OutputOverrun` for result size).
pub fn delta_sizes(delta: &[u8]) -> Result<(usize, usize), DeltaError> {
    let mut pos = 0usize;
    let base_size = delta_size_to_usize(
        read_leb128_u64(delta, &mut pos)?,
        DeltaError::BaseSizeMismatch,
    )?;
    let result_size =
        delta_size_to_usize(read_leb128_u64(delta, &mut pos)?, DeltaError::OutputOverrun)?;
    Ok((base_size, result_size))
}

#[inline(always)]
fn parse_delta_header(
    base: &[u8],
    delta: &[u8],
    max_out: usize,
) -> Result<(usize, usize), DeltaError> {
    let mut pos = 0usize;
    let base_size = delta_size_to_usize(
        read_leb128_u64(delta, &mut pos)?,
        DeltaError::BaseSizeMismatch,
    )?;
    let result_size =
        delta_size_to_usize(read_leb128_u64(delta, &mut pos)?, DeltaError::OutputOverrun)?;
    if base_size != base.len() {
        return Err(DeltaError::BaseSizeMismatch);
    }
    if result_size > max_out {
        return Err(DeltaError::OutputOverrun);
    }
    Ok((pos, result_size))
}

/// Executes delta body opcodes and emits contiguous output chunks.
///
/// Shared by `apply_delta` and `apply_delta_into`; both callsites keep only
/// sink-specific write behavior while command decoding and bounds checks stay
/// centralized here.
#[inline(always)]
fn interpret_delta_body(
    base: &[u8],
    delta: &[u8],
    mut pos: usize,
    result_size: usize,
    mut emit_chunk: impl FnMut(&[u8]) -> Result<(), DeltaError>,
) -> Result<(), DeltaError> {
    let mut out_len = 0usize;
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;

        if (cmd & 0x80) != 0 {
            let (off, size) = decode_copy_params(delta, &mut pos, cmd)?;
            let end = off.checked_add(size).ok_or(DeltaError::CopyOutOfRange)?;
            if end > base.len() {
                return Err(DeltaError::CopyOutOfRange);
            }
            let out_end = out_len.checked_add(size).ok_or(DeltaError::OutputOverrun)?;
            if out_end > result_size {
                return Err(DeltaError::OutputOverrun);
            }

            debug_assert!(off + size <= base.len());
            emit_chunk(&base[off..end])?;
            out_len = out_end;
        } else if cmd != 0 {
            let size = cmd as usize;
            if delta.len() - pos < size {
                return Err(DeltaError::Truncated);
            }
            let out_end = out_len.checked_add(size).ok_or(DeltaError::OutputOverrun)?;
            if out_end > result_size {
                return Err(DeltaError::OutputOverrun);
            }

            debug_assert!(pos + size <= delta.len());
            emit_chunk(&delta[pos..pos + size])?;
            pos += size;
            out_len = out_end;
        } else {
            return Err(DeltaError::BadCommandZero);
        }
    }

    if out_len != result_size {
        return Err(DeltaError::ResultSizeMismatch);
    }
    Ok(())
}

/// Apply a git delta buffer to `base`, writing directly into `out`.
///
/// The caller supplies `max_out` as a hard safety cap to prevent allocating
/// unbounded output on corrupt deltas.
///
/// The delta format encodes both base size and result size as varints at the
/// head of the stream; both are validated.
///
/// The output buffer is cleared before writing. Writes directly into
/// pre-reserved spare capacity, eliminating per-chunk bounds checking and
/// length updates on the hot delta-application path.
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<(), DeltaError> {
    out.clear();

    let (pos, result_size) = parse_delta_header(base, delta, max_out)?;
    out.reserve(result_size);
    poison_spare_capacity(out);
    debug_assert!(
        out.capacity() >= result_size,
        "reserve did not allocate enough"
    );

    let mut written = 0usize;
    // SAFETY — pointer stability invariant:
    // `out.reserve(result_size)` above pre-allocates all needed capacity.
    // `out_ptr` is valid for writes up to `result_size` bytes from this
    // point until `set_len(written)` below. NO Vec methods (push, extend,
    // reserve, etc.) may be called on `out` in between — any such call
    // could reallocate, invalidating `out_ptr` and causing use-after-free.
    // The loop below uses ONLY raw pointer writes via `copy_nonoverlapping`.
    let out_ptr = out.as_mut_ptr();

    interpret_delta_body(base, delta, pos, result_size, |chunk| {
        let size = chunk.len();
        debug_assert!(written + size <= result_size);

        // SAFETY:
        // 1. Bounds: `interpret_delta_body` validates chunk source bounds and
        //    enforces `written + size <= result_size` before emitting.
        // 2. Pointer stability: `out_ptr` is valid because no Vec methods are
        //    called between `as_mut_ptr()` and `set_len()` (see invariant above).
        // 3. Destination: `written + size <= result_size <= capacity`.
        // 4. No aliasing: chunks reference `base` or `delta` (both `&[u8]`),
        //    disjoint from `out: &mut Vec<u8>` (enforced by borrow checker).
        unsafe {
            std::ptr::copy_nonoverlapping(chunk.as_ptr(), out_ptr.add(written), size);
        }
        written += size;
        Ok(())
    })?;

    debug_assert_eq!(written, result_size);
    if written > result_size || written > out.capacity() {
        return Err(DeltaError::OutputOverrun);
    }

    // SAFETY:
    // 1. Initialization: exactly `written == result_size` bytes written above
    //    via `copy_nonoverlapping` from validated source slices.
    // 2. Bounds: `written <= result_size <= capacity` (from `out.reserve`).
    // 3. Pointer stability: no Vec methods called since `as_mut_ptr()`.
    unsafe { out.set_len(written) };
    Ok(())
}

/// Apply a git delta buffer to `base`, streaming output into a sink.
///
/// The sink is invoked with contiguous output slices. The total output is
/// validated against the delta header's result size. Chunks may reference
/// either the input `base` or the delta payload.
pub fn apply_delta_into(
    base: &[u8],
    delta: &[u8],
    max_out: usize,
    mut on_chunk: impl FnMut(&[u8]) -> Result<(), DeltaError>,
) -> Result<usize, DeltaError> {
    let (pos, result_size) = parse_delta_header(base, delta, max_out)?;
    interpret_delta_body(base, delta, pos, result_size, |chunk| on_chunk(chunk))?;

    Ok(result_size)
}

/// Decodes copy parameters for a delta copy instruction.
///
/// A zero size encodes 0x10000, per Git's delta format.
///
/// Bit layout follows the Git delta specification:
/// - Low bits select which offset bytes are present (little-endian).
/// - High bits select which size bytes are present.
///
/// This path is on the delta-copy hot loop. We pre-compute the total number of
/// parameter bytes and perform one bounds check up front, then decode with
/// tight predictable branches.
#[inline(always)]
fn decode_copy_params(
    delta: &[u8],
    pos: &mut usize,
    cmd: u8,
) -> Result<(usize, usize), DeltaError> {
    let off_mask = cmd & 0x0f;
    let size_mask = (cmd >> 4) & 0x07;
    let needed = (off_mask.count_ones() + size_mask.count_ones()) as usize;
    let start = *pos;
    let end = start.checked_add(needed).ok_or(DeltaError::Truncated)?;
    if end > delta.len() {
        *pos = delta.len();
        return Err(DeltaError::Truncated);
    }

    // SAFETY: `cursor` starts at `start` and is incremented exactly once per set bit
    // in off_mask (4 bits) then size_mask (3 bits). Total increments =
    // count_ones(off_mask) + count_ones(size_mask) = `needed`. The upfront check
    // `end > delta.len()` where `end = start + needed` guarantees all accessed
    // indices are in-bounds: at each access, cursor < start + needed = end <= delta.len().
    // Verified by exhaustive test over all 128 mask combos and Miri.
    let mut cursor = start;
    let mut off: usize = 0;
    let mut size: usize = 0;
    debug_assert!(
        end <= delta.len(),
        "decode_copy_params: end ({end}) > delta.len() ({len})",
        len = delta.len()
    );
    // SAFETY: `cursor` bounds are validated above by proving
    // `start <= cursor < end <= delta.len()` for every read in this block.
    unsafe {
        if (off_mask & 0x01) != 0 {
            off |= *delta.get_unchecked(cursor) as usize;
            cursor += 1;
        }
        if (off_mask & 0x02) != 0 {
            off |= (*delta.get_unchecked(cursor) as usize) << 8;
            cursor += 1;
        }
        if (off_mask & 0x04) != 0 {
            off |= (*delta.get_unchecked(cursor) as usize) << 16;
            cursor += 1;
        }
        if (off_mask & 0x08) != 0 {
            off |= (*delta.get_unchecked(cursor) as usize) << 24;
            cursor += 1;
        }

        if (size_mask & 0x01) != 0 {
            size |= *delta.get_unchecked(cursor) as usize;
            cursor += 1;
        }
        if (size_mask & 0x02) != 0 {
            size |= (*delta.get_unchecked(cursor) as usize) << 8;
            cursor += 1;
        }
        if (size_mask & 0x04) != 0 {
            size |= (*delta.get_unchecked(cursor) as usize) << 16;
            cursor += 1;
        }
    }
    debug_assert_eq!(
        cursor.wrapping_sub(start),
        needed,
        "cursor advanced past bounds"
    );
    *pos = cursor;

    if size == 0 {
        size = 0x10000;
    }

    Ok((off, size))
}

#[cfg(test)]
mod tests {
    use super::super::delta_test_helpers::{
        make_add_delta, make_copy_delta, push_varint, push_varint_u64, zlib_compress,
        SyntheticPackBuilder,
    };
    use super::super::object_id::OidBytes;
    use super::*;

    #[test]
    fn decode_copy_params_reads_all_selected_fields() {
        let delta = [0x11_u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let cmd = 0x80 | 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40;
        let mut pos = 0_usize;
        let (off, size) = decode_copy_params(&delta, &mut pos, cmd).expect("decode copy params");
        assert_eq!(off, 0x4433_2211);
        assert_eq!(size, 0x0077_6655);
        assert_eq!(pos, delta.len());
    }

    #[test]
    fn decode_copy_params_zero_size_expands_to_64k() {
        let delta = [0x2a_u8];
        let cmd = 0x80 | 0x01; // copy with 1-byte offset, implicit 64 KiB size
        let mut pos = 0_usize;
        let (off, size) = decode_copy_params(&delta, &mut pos, cmd).expect("decode copy params");
        assert_eq!(off, 0x2a);
        assert_eq!(size, 0x1_0000);
        assert_eq!(pos, 1);
    }

    #[test]
    fn decode_copy_params_truncated_when_flagged_bytes_missing() {
        let delta = [0xaa_u8, 0xbb];
        let cmd = 0x80 | 0x01 | 0x02 | 0x10;
        let mut pos = 0_usize;
        let err = decode_copy_params(&delta, &mut pos, cmd).expect_err("expected truncation");
        assert_eq!(err, DeltaError::Truncated);
        assert_eq!(
            pos,
            delta.len(),
            "position should match legacy truncation behavior"
        );
    }

    /// Exhaustive test covering all 128 (off_mask × size_mask) combinations.
    ///
    /// For each combination we build a delta payload with known byte values
    /// and verify decode_copy_params produces the expected offset and size.
    #[test]
    fn decode_copy_params_all_128_mask_combos() {
        // off_mask: 4 bits (0..16), size_mask: 3 bits (0..8) → 128 combos.
        for off_mask in 0u8..16 {
            for size_mask in 0u8..8 {
                let cmd = 0x80 | off_mask | (size_mask << 4);
                let needed = (off_mask.count_ones() + size_mask.count_ones()) as usize;

                // Build payload: byte values 0x10, 0x20, 0x30, … so each is distinct.
                let payload: Vec<u8> = (0..needed).map(|i| ((i as u8) + 1) * 0x10).collect();

                let mut pos = 0usize;
                let (off, size) = decode_copy_params(&payload, &mut pos, cmd)
                    .unwrap_or_else(|_| panic!("off_mask={off_mask:#x} size_mask={size_mask:#x}"));
                assert_eq!(
                    pos, needed,
                    "pos mismatch for off_mask={off_mask:#x} size_mask={size_mask:#x}"
                );

                // Reconstruct expected offset.
                let mut expected_off: usize = 0;
                let mut idx = 0;
                if (off_mask & 0x01) != 0 {
                    expected_off |= payload[idx] as usize;
                    idx += 1;
                }
                if (off_mask & 0x02) != 0 {
                    expected_off |= (payload[idx] as usize) << 8;
                    idx += 1;
                }
                if (off_mask & 0x04) != 0 {
                    expected_off |= (payload[idx] as usize) << 16;
                    idx += 1;
                }
                if (off_mask & 0x08) != 0 {
                    expected_off |= (payload[idx] as usize) << 24;
                    idx += 1;
                }
                assert_eq!(
                    off, expected_off,
                    "off mismatch for off_mask={off_mask:#x} size_mask={size_mask:#x}"
                );

                // Reconstruct expected size.
                let mut expected_size: usize = 0;
                if (size_mask & 0x01) != 0 {
                    expected_size |= payload[idx] as usize;
                    idx += 1;
                }
                if (size_mask & 0x02) != 0 {
                    expected_size |= (payload[idx] as usize) << 8;
                    idx += 1;
                }
                if (size_mask & 0x04) != 0 {
                    expected_size |= (payload[idx] as usize) << 16;
                    idx += 1;
                }
                if expected_size == 0 {
                    expected_size = 0x10000;
                }
                assert_eq!(
                    size, expected_size,
                    "size mismatch for off_mask={off_mask:#x} size_mask={size_mask:#x}"
                );
                let _ = idx; // suppress unused warning
            }
        }
    }

    #[test]
    fn apply_delta_copy_instruction() {
        let base = b"Hello, World!";
        // Copy entire base
        let delta = make_copy_delta(base.len(), 0, base.len());

        let mut out = Vec::new();
        apply_delta(base, &delta, &mut out, 1024).expect("apply_delta copy");
        assert_eq!(out, base);
    }

    #[test]
    fn apply_delta_copy_partial() {
        let base = b"ABCDEFGHIJ";
        // Copy bytes 3..7 ("DEFG")
        let delta = make_copy_delta(base.len(), 3, 4);

        let mut out = Vec::new();
        apply_delta(base, &delta, &mut out, 1024).expect("apply_delta partial copy");
        assert_eq!(&out, b"DEFG");
    }

    #[test]
    fn apply_delta_add_literal() {
        let base = b"unused-base";
        let literal = b"literal data";
        let delta = make_add_delta(base.len(), literal);

        let mut out = Vec::new();
        apply_delta(base, &delta, &mut out, 1024).expect("apply_delta add");
        assert_eq!(&out, literal);
    }

    #[test]
    fn apply_delta_mixed_copy_and_add() {
        let base = b"ABCDEFGHIJ";
        let mut delta = Vec::new();
        // Header: base_size=10, result_size=9 ("ABCDE" + "XYZ" + "J")
        push_varint(10, &mut delta);
        push_varint(9, &mut delta);
        // Copy 5 bytes from offset 0 ("ABCDE")
        delta.push(0x80 | 0x01 | 0x10); // copy, 1-byte offset, 1-byte size
        delta.push(0x00); // offset = 0
        delta.push(0x05); // size = 5
                          // Add 3 literal bytes ("XYZ")
        delta.push(0x03);
        delta.extend_from_slice(b"XYZ");
        // Copy 1 byte from offset 9 ("J")
        delta.push(0x80 | 0x01 | 0x10); // copy
        delta.push(0x09); // offset = 9
        delta.push(0x01); // size = 1

        let mut out = Vec::new();
        apply_delta(base, &delta, &mut out, 1024).expect("apply_delta mixed");
        assert_eq!(&out, b"ABCDEXYZJ");
    }

    #[test]
    fn apply_delta_base_size_mismatch() {
        let base = b"short";
        let mut delta = Vec::new();
        push_varint(100, &mut delta); // claims base is 100 bytes
        push_varint(5, &mut delta);

        let mut out = Vec::new();
        let err = apply_delta(base, &delta, &mut out, 1024).unwrap_err();
        assert_eq!(err, DeltaError::BaseSizeMismatch);
    }

    #[test]
    fn apply_delta_rejects_base_size_truncation_candidate() {
        // 2^32 would truncate to 0 on 32-bit if converted with `as usize`.
        let mut delta = Vec::new();
        push_varint_u64(u64::from(u32::MAX) + 1, &mut delta);
        push_varint(0, &mut delta);

        let mut out = Vec::new();
        let err = apply_delta(&[], &delta, &mut out, 0).unwrap_err();
        assert_eq!(err, DeltaError::BaseSizeMismatch);
    }

    #[test]
    fn apply_delta_rejects_result_size_truncation_candidate() {
        // 2^32 would truncate to 0 on 32-bit if converted with `as usize`.
        let mut delta = Vec::new();
        push_varint(0, &mut delta);
        push_varint_u64(u64::from(u32::MAX) + 1, &mut delta);

        let mut out = Vec::new();
        let err = apply_delta(&[], &delta, &mut out, 0).unwrap_err();
        assert_eq!(err, DeltaError::OutputOverrun);
    }

    #[test]
    fn delta_sizes_checks_result_size_usize_conversion() {
        let mut delta = Vec::new();
        push_varint(0, &mut delta);
        let large = u64::from(u32::MAX) + 1;
        push_varint_u64(large, &mut delta);

        let parsed = delta_sizes(&delta);
        if usize::BITS == 32 {
            assert_eq!(parsed.unwrap_err(), DeltaError::OutputOverrun);
        } else {
            assert_eq!(
                parsed.unwrap(),
                (
                    0,
                    usize::try_from(large).expect("value must fit on non-32-bit targets")
                )
            );
        }
    }

    #[test]
    fn apply_delta_result_exceeds_max_out() {
        let base = b"base";
        let mut delta = Vec::new();
        push_varint(4, &mut delta);
        push_varint(1000, &mut delta); // result_size 1000

        let mut out = Vec::new();
        let err = apply_delta(base, &delta, &mut out, 100).unwrap_err(); // max_out 100
        assert_eq!(err, DeltaError::OutputOverrun);
    }

    #[test]
    fn apply_delta_bad_command_zero() {
        let base = b"data";
        let mut delta = Vec::new();
        push_varint(4, &mut delta);
        push_varint(4, &mut delta);
        delta.push(0x00); // command zero is invalid

        let mut out = Vec::new();
        let err = apply_delta(base, &delta, &mut out, 1024).unwrap_err();
        assert_eq!(err, DeltaError::BadCommandZero);
    }

    #[test]
    fn apply_delta_copy_out_of_range() {
        let base = b"short";
        let mut delta = Vec::new();
        push_varint(5, &mut delta);
        push_varint(10, &mut delta);
        // Copy 10 bytes from offset 0, but base is only 5 bytes
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(0x00); // offset 0
        delta.push(0x0a); // size 10

        let mut out = Vec::new();
        let err = apply_delta(base, &delta, &mut out, 1024).unwrap_err();
        assert_eq!(err, DeltaError::CopyOutOfRange);
    }

    #[test]
    fn apply_delta_truncated_add() {
        let base = b"data";
        let mut delta = Vec::new();
        push_varint(4, &mut delta);
        push_varint(5, &mut delta);
        delta.push(0x05); // add 5 bytes, but supply none

        let mut out = Vec::new();
        let err = apply_delta(base, &delta, &mut out, 1024).unwrap_err();
        assert_eq!(err, DeltaError::Truncated);
    }

    #[test]
    fn apply_delta_result_size_mismatch() {
        let base = b"ABCDEFGHIJ";
        let mut delta = Vec::new();
        push_varint(10, &mut delta);
        push_varint(10, &mut delta); // promises 10 bytes
                                     // But only copy 5
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(0x00);
        delta.push(0x05);

        let mut out = Vec::new();
        let err = apply_delta(base, &delta, &mut out, 1024).unwrap_err();
        assert_eq!(err, DeltaError::ResultSizeMismatch);
    }

    #[test]
    fn apply_delta_empty_delta_body() {
        // Delta with base_size=0, result_size=0, and no instructions.
        let base: &[u8] = &[];
        let mut delta = Vec::new();
        push_varint(0, &mut delta);
        push_varint(0, &mut delta);

        let mut out = Vec::new();
        apply_delta(base, &delta, &mut out, 1024).expect("empty delta");
        assert!(out.is_empty());
    }

    #[test]
    fn apply_delta_output_reuses_vec() {
        // Verify out is cleared and old contents don't leak.
        let base = b"ABCD";
        let delta = make_copy_delta(4, 0, 4);

        let mut out = Vec::from("leftover garbage data that should be cleared");
        apply_delta(base, &delta, &mut out, 1024).expect("reuse vec");
        assert_eq!(&out, b"ABCD");
    }

    #[test]
    fn inflate_limited_with_basic_round_trip() {
        let original = b"Hello, this is test data for inflate_limited_with!";
        let compressed = zlib_compress(original);

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let consumed =
            inflate_limited_with(&mut de, &compressed, &mut out, 1024).expect("inflate basic");

        assert_eq!(consumed, compressed.len());
        assert_eq!(&out, original);
    }

    #[test]
    fn inflate_limited_with_exact_max_out() {
        // Decompress data whose uncompressed size exactly equals max_out.
        let original = vec![0xAB_u8; 256];
        let compressed = zlib_compress(&original);

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let consumed =
            inflate_limited_with(&mut de, &compressed, &mut out, 256).expect("inflate exact");

        assert_eq!(consumed, compressed.len());
        assert_eq!(out, original);
    }

    #[test]
    fn inflate_limited_with_exceeds_max_out() {
        // Data decompresses to 256 bytes but max_out is 100.
        let original = vec![0xCD_u8; 256];
        let compressed = zlib_compress(&original);

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let err = inflate_limited_with(&mut de, &compressed, &mut out, 100).unwrap_err();

        assert_eq!(err, InflateError::LimitExceeded);
        // Partial output may have been written, but it must not exceed max_out.
        assert!(out.len() <= 100);
    }

    #[test]
    fn inflate_limited_with_empty_input() {
        // Empty compressed data is not valid zlib — should error.
        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let result = inflate_limited_with(&mut de, &[], &mut out, 1024);

        assert!(result.is_err());
    }

    #[test]
    fn inflate_limited_with_corrupt_input() {
        // Garbage bytes are not valid zlib.
        let garbage = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let result = inflate_limited_with(&mut de, &garbage, &mut out, 1024);

        assert!(result.is_err());
    }

    #[test]
    fn inflate_limited_with_reuses_decompress() {
        // Call inflate_limited_with twice with the same Decompress instance.
        // The function should reset internally.
        let original1 = b"First payload";
        let original2 = b"Second payload, slightly different";
        let compressed1 = zlib_compress(original1);
        let compressed2 = zlib_compress(original2);

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();

        inflate_limited_with(&mut de, &compressed1, &mut out, 1024).expect("inflate first");
        assert_eq!(&out, original1);

        inflate_limited_with(&mut de, &compressed2, &mut out, 1024).expect("inflate second");
        assert_eq!(&out, original2.as_slice());
    }

    #[test]
    fn inflate_limited_with_zero_byte_output() {
        // Compress empty data — decompresses to 0 bytes.
        let compressed = zlib_compress(&[]);

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let consumed =
            inflate_limited_with(&mut de, &compressed, &mut out, 1024).expect("inflate empty");

        assert_eq!(consumed, compressed.len());
        assert!(out.is_empty());
    }

    #[test]
    fn inflate_limited_with_zero_max_out_allows_empty_stream() {
        let compressed = zlib_compress(&[]);

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let consumed =
            inflate_limited_with(&mut de, &compressed, &mut out, 0).expect("inflate empty");

        assert_eq!(consumed, compressed.len());
        assert!(out.is_empty());
    }

    #[test]
    fn inflate_limited_with_zero_max_out_rejects_non_empty_stream() {
        let compressed = zlib_compress(b"non-empty output");

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let err = inflate_limited_with(&mut de, &compressed, &mut out, 0).unwrap_err();

        assert_eq!(err, InflateError::LimitExceeded);
        assert!(out.is_empty());
    }

    #[test]
    fn inflate_limited_with_zero_max_out_header_only_zlib_is_truncated() {
        // Bare zlib header without any deflate block or trailer.
        let malformed = b"\x78\x01";

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let err = inflate_limited_with(&mut de, malformed, &mut out, 0).unwrap_err();

        assert_eq!(err, InflateError::TruncatedInput);
        assert!(out.is_empty());
    }

    #[test]
    fn inflate_limited_with_clears_existing_output() {
        // out has stale data; inflate_limited_with should clear it.
        let original = b"fresh output";
        let compressed = zlib_compress(original);

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::from("stale garbage that should be cleared");
        inflate_limited_with(&mut de, &compressed, &mut out, 1024).expect("inflate clear");
        assert_eq!(&out, original);
    }

    #[test]
    fn apply_delta_into_copy_zero_size_round_trip() {
        let base = vec![0xa5_u8; 0x1_0000];
        let mut delta = Vec::new();
        push_varint(base.len(), &mut delta);
        push_varint(base.len(), &mut delta);
        delta.push(0x80); // copy from offset 0, implicit 64 KiB

        let mut out = Vec::new();
        let written = apply_delta_into(&base, &delta, base.len(), |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })
        .expect("apply delta");

        assert_eq!(written, base.len());
        assert_eq!(out, base);
    }

    /// Miri target: exercises inflate_limited_with spare-capacity write + set_len.
    #[test]
    fn inflate_limited_with_miri_roundtrip() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let original = b"hello miri roundtrip test data";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let consumed = inflate_limited_with(&mut de, &compressed, &mut out, 256).unwrap();
        assert_eq!(out, original);
        assert_eq!(consumed, compressed.len());
    }

    /// Miri target: exercises apply_delta raw-pointer copy and insert paths.
    #[test]
    fn apply_delta_miri_copy_and_insert() {
        let base = b"ABCDEFGHIJ";
        // Delta: base_size=10, result_size=8, copy 4 bytes from off=2, insert 4 literal bytes.
        let delta: &[u8] = &[
            10, // base_size varint
            8,  // result_size varint
            0x80 | 0x01 | 0x10,
            2,
            4, // copy: off=2, size=4 -> "CDEF"
            4,
            b'X',
            b'Y',
            b'Z',
            b'W', // insert 4 bytes -> "XYZW"
        ];
        let mut out = Vec::new();
        apply_delta(base, delta, &mut out, 64).unwrap();
        assert_eq!(&out, b"CDEFXYZW");
    }

    #[test]
    fn poison_spare_capacity_writes_debug_pattern() {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"hello");
        super::poison_spare_capacity(&mut buf);

        // The logical content must be unchanged.
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(buf.len(), 5);

        // In debug builds, spare bytes should be 0xDE.
        // In release builds, poison_spare_capacity is a no-op, so the spare
        // region is uninitialized — reading it would be UB.
        #[cfg(debug_assertions)]
        {
            let spare = buf.spare_capacity_mut();
            for (i, slot) in spare.iter().enumerate() {
                // SAFETY: we just wrote 0xDE to every spare slot in debug mode.
                let val = unsafe { slot.assume_init() };
                assert_eq!(val, 0xDE, "spare byte {i} not poisoned");
            }
        }
    }

    #[test]
    fn inflate_with_poison_round_trip() {
        // Verify that poisoning spare capacity does not break inflate.
        let original = b"inflate with poison test payload data";
        let compressed = zlib_compress(original);

        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let consumed = inflate_limited_with(&mut de, &compressed, &mut out, 1024)
            .expect("inflate with poison");

        assert_eq!(consumed, compressed.len());
        assert_eq!(&out[..], original.as_slice());
    }

    #[test]
    fn apply_delta_with_poison_round_trip() {
        // Verify that poisoning spare capacity does not break delta application.
        let base = b"ABCDEFGHIJ";
        let delta = make_copy_delta(base.len(), 0, base.len());

        let mut out = Vec::new();
        apply_delta(base, &delta, &mut out, 1024).expect("apply delta with poison");
        assert_eq!(&out[..], base.as_slice());
        // Mixed copy+add delta is already exercised by
        // `apply_delta_mixed_copy_and_add`; no need to duplicate it here.
    }

    #[test]
    fn ref_delta_entry_header_parses_oid() {
        let base_data = b"hello base";
        let delta_data = make_add_delta(base_data.len(), b"XY");

        let base_oid = OidBytes::try_from_slice(&[0xAB; 20]).unwrap();

        let mut builder = SyntheticPackBuilder::new();
        builder.add_non_delta(3, base_data);
        let ref_idx = builder.add_ref_delta(base_oid, &delta_data);

        let (pack, offsets) = builder.build();
        let pf = PackFile::parse(&pack, 20).expect("parse pack");

        let header = pf
            .entry_header_at(offsets[ref_idx], 64)
            .expect("parse ref delta header");

        assert_eq!(
            header.kind,
            EntryKind::RefDelta { base_oid },
            "should parse REF_DELTA with correct base OID"
        );
        assert_eq!(header.size, delta_data.len() as u64);
        // data_start must point past the 20-byte OID to the compressed
        // delta payload.
        let slice = pf.slice_from(header.data_start);
        assert!(
            !slice.is_empty(),
            "data_start should point to compressed delta bytes"
        );
    }
}
