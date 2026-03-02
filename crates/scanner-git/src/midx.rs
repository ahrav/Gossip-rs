//! Zero-copy multi-pack index (MIDX) parser.
//!
//! Parses and validates the MIDX structure, providing pack lookup for
//! tree object loading. The view is zero-copy: all slices reference the
//! original MIDX byte buffer, which must outlive the `MidxView`.
//!
//! # Scope
//! - Supports MIDX version 1 only.
//! - Validates chunk table shape, fanout monotonicity, and chunk sizes.
//! - Does **not** validate pack checksums or the trailing MIDX checksum.
//!
//! # Complexity
//! - `find_oid` is `O(log N)` via fanout-bucketed binary search.
//! - `find_oid_sorted` is `O(k log(N/k))` via galloping search over
//!   fanout-bucketed ranges, reusing a cursor for sorted input.
//! - `offset_at` is `O(1)` and may follow a LOFF indirection.

use std::collections::HashSet;

use super::midx_error::{ChunkId, MidxError};
use super::object_id::{ObjectFormat, OidBytes};

/// MIDX magic bytes.
const MIDX_MAGIC: [u8; 4] = *b"MIDX";
/// MIDX version 1 (only supported version).
const MIDX_VERSION: u8 = 1;
/// MIDX header size (12 bytes).
const MIDX_HEADER_SIZE: usize = 12;
/// Chunk table entry size (12 bytes: 4 ID + 8 offset).
const CHUNK_ENTRY_SIZE: usize = 12;
/// PNAM chunk ID (pack names).
const CHUNK_PNAM: [u8; 4] = *b"PNAM";
/// OIDF chunk ID (OID fanout).
const CHUNK_OIDF: [u8; 4] = *b"OIDF";
/// OIDL chunk ID (OID list).
const CHUNK_OIDL: [u8; 4] = *b"OIDL";
/// OOFF chunk ID (object offsets).
const CHUNK_OOFF: [u8; 4] = *b"OOFF";
/// LOFF chunk ID (large offsets, optional).
const CHUNK_LOFF: [u8; 4] = *b"LOFF";
/// Fanout table entries.
const FANOUT_ENTRIES: usize = 256;
/// Fanout table size in bytes.
const FANOUT_SIZE: usize = FANOUT_ENTRIES * 4;
/// MSB mask for detecting LOFF indirection in OOFF entries.
const LOFF_FLAG: u32 = 0x8000_0000;
/// Maximum MIDX file size (4 GB).
const MAX_MIDX_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Zero-copy view over a multi-pack index.
///
/// # Invariants
/// - All chunk slices are validated to lie within the MIDX buffer.
/// - `object_count` equals the last value in the fanout table.
/// - `oid_len` matches the repository object format.
/// - Base MIDX layers are not supported; only the top-level index is parsed.
#[derive(Debug, Clone, Copy)]
pub struct MidxView<'a> {
    format: ObjectFormat,
    pack_count: u32,
    object_count: u32,
    pnam: &'a [u8],
    oidf: &'a [u8],
    oidl: &'a [u8],
    ooff: &'a [u8],
    loff: Option<&'a [u8]>,
}

/// Cursor state for streaming sorted OID lookups.
///
/// `next_idx` advances monotonically within the current fanout bucket.
#[derive(Debug, Default, Clone, Copy)]
pub struct MidxCursor {
    next_idx: u32,
    bucket_end: u32,
    bucket_first: Option<u8>,
}

#[derive(Clone, Copy, Debug)]
struct ChunkLoc {
    id: [u8; 4],
    offset: u64,
    len: u64,
}

impl<'a> MidxView<'a> {
    /// Parses a MIDX from raw bytes.
    ///
    /// This parser is zero-copy: all returned slices borrow from `data`.
    /// The trailing MIDX checksum is not validated.
    ///
    /// # Errors
    /// Returns `MidxError` if the file is malformed, has unsupported version,
    /// contains inconsistent chunk sizes, or doesn't match the repo's OID
    /// length. This routine performs no allocation beyond small vectors.
    pub fn parse(data: &'a [u8], expected_format: ObjectFormat) -> Result<Self, MidxError> {
        if data.len() as u64 > MAX_MIDX_SIZE {
            return Err(MidxError::MidxTooLarge {
                size: data.len() as u64,
                max: MAX_MIDX_SIZE,
            });
        }

        if data.len() < MIDX_HEADER_SIZE + CHUNK_ENTRY_SIZE {
            return Err(MidxError::corrupt("file too small"));
        }

        let magic = &data[0..4];
        if magic != MIDX_MAGIC {
            return Err(MidxError::corrupt("invalid magic"));
        }

        let version = data[4];
        if version != MIDX_VERSION {
            return Err(MidxError::UnsupportedMidxVersion { version });
        }

        let hash_version = data[5];
        let format = match hash_version {
            1 => ObjectFormat::Sha1,
            2 => ObjectFormat::Sha256,
            _ => return Err(MidxError::corrupt("invalid hash version")),
        };

        if format != expected_format {
            return Err(MidxError::OidLengthMismatch {
                midx_oid_len: format.oid_len(),
                repo_oid_len: expected_format.oid_len(),
            });
        }

        let chunk_count = data[6];
        let _base_count = data[7];
        let pack_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        if pack_count > u16::MAX as u32 {
            return Err(MidxError::PackCountOverflow { count: pack_count });
        }

        let chunks = Self::parse_chunk_table(data, chunk_count)?;

        let pnam_loc = Self::require_chunk(&chunks, CHUNK_PNAM)?;
        let oidf_loc = Self::require_chunk(&chunks, CHUNK_OIDF)?;
        let oidl_loc = Self::require_chunk(&chunks, CHUNK_OIDL)?;
        let ooff_loc = Self::require_chunk(&chunks, CHUNK_OOFF)?;
        let loff_loc = Self::find_chunk(&chunks, CHUNK_LOFF);

        if oidf_loc.len != FANOUT_SIZE as u64 {
            return Err(MidxError::InvalidChunkSize {
                chunk_id: ChunkId::new(CHUNK_OIDF),
                actual: oidf_loc.len,
                expected: FANOUT_SIZE as u64,
            });
        }

        let pnam = Self::slice_chunk(data, &pnam_loc)?;
        let oidf = Self::slice_chunk(data, &oidf_loc)?;
        let oidl = Self::slice_chunk(data, &oidl_loc)?;
        let ooff = Self::slice_chunk(data, &ooff_loc)?;
        let loff = match loff_loc {
            Some(loc) => Some(Self::slice_chunk(data, &loc)?),
            None => None,
        };

        let object_count = Self::validate_fanout(oidf)?;

        let oid_len = format.oid_len() as usize;
        let expected_oidl_size = object_count as usize * oid_len;
        if oidl.len() != expected_oidl_size {
            return Err(MidxError::InvalidChunkSize {
                chunk_id: ChunkId::new(CHUNK_OIDL),
                actual: oidl.len() as u64,
                expected: expected_oidl_size as u64,
            });
        }

        let expected_ooff_size = object_count as usize * 8;
        if ooff.len() != expected_ooff_size {
            return Err(MidxError::InvalidChunkSize {
                chunk_id: ChunkId::new(CHUNK_OOFF),
                actual: ooff.len() as u64,
                expected: expected_ooff_size as u64,
            });
        }

        if let Some(loff_data) = loff {
            if loff_data.len() % 8 != 0 {
                return Err(MidxError::corrupt("LOFF size not multiple of 8"));
            }
        }

        Self::validate_pnam(pnam, pack_count)?;

        Ok(Self {
            format,
            pack_count,
            object_count,
            pnam,
            oidf,
            oidl,
            ooff,
            loff,
        })
    }

    /// Returns the number of packs referenced.
    #[inline]
    pub fn pack_count(&self) -> u32 {
        self.pack_count
    }

    /// Returns the number of objects indexed.
    #[inline]
    pub fn object_count(&self) -> u32 {
        self.object_count
    }

    /// Returns the OID length in bytes.
    #[inline]
    pub const fn oid_len(&self) -> u8 {
        self.format.oid_len()
    }

    /// Returns the fanout value for a first-byte value.
    ///
    /// This value is the upper bound (exclusive) of the bucket for that
    /// first byte in the OID list.
    #[inline]
    pub fn fanout(&self, first_byte: u8) -> u32 {
        let off = first_byte as usize * 4;
        u32::from_be_bytes([
            self.oidf[off],
            self.oidf[off + 1],
            self.oidf[off + 2],
            self.oidf[off + 3],
        ])
    }

    /// Returns the OID bytes at the given OIDL index.
    ///
    /// # Panics
    /// Panics if `idx` is out of range (debug_assert on index; slice bounds in all builds).
    #[inline]
    pub fn oid_at(&self, idx: u32) -> &[u8] {
        debug_assert!(idx < self.object_count, "OID index out of bounds");
        let oid_len = self.oid_len() as usize;
        let start = idx as usize * oid_len;
        &self.oidl[start..start + oid_len]
    }

    /// Returns the (pack_id, offset) for the object at the given index.
    ///
    /// `pack_id` is a u16 pack position in PNAM order. `offset` is a byte
    /// offset within the pack file. For large offsets, an LOFF indirection
    /// is resolved.
    ///
    /// # Errors
    /// Returns `LoffIndexOutOfBounds` if the LOFF indirection is invalid,
    /// or `PackPosOutOfBounds` if the pack position exceeds the pack count.
    pub fn offset_at(&self, idx: u32) -> Result<(u16, u64), MidxError> {
        debug_assert!(idx < self.object_count, "offset index out of bounds");

        let entry_start = idx as usize * 8;
        let entry = &self.ooff[entry_start..entry_start + 8];

        let pack_pos = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let offset_raw = u32::from_be_bytes([entry[4], entry[5], entry[6], entry[7]]);

        if pack_pos >= self.pack_count {
            return Err(MidxError::PackPosOutOfBounds {
                pack_pos,
                pack_count: self.pack_count,
            });
        }
        let pack_id = pack_pos as u16;

        let offset = if offset_raw & LOFF_FLAG != 0 {
            let loff_idx = offset_raw & !LOFF_FLAG;
            self.resolve_loff(loff_idx)?
        } else {
            offset_raw as u64
        };

        Ok((pack_id, offset))
    }

    /// Returns an iterator over pack names from PNAM.
    ///
    /// Names are raw bytes (not validated UTF-8) and exclude the trailing NUL.
    pub fn pack_names(&self) -> impl Iterator<Item = &'a [u8]> {
        self.pnam.split(|&b| b == 0).filter(|s| !s.is_empty())
    }

    /// Verifies that all actual pack files are referenced in the MIDX.
    ///
    /// The comparison is normalized to strip `.pack`/`.idx` suffixes.
    pub fn verify_completeness<'b, I>(&self, actual_packs: I) -> Result<(), MidxError>
    where
        I: IntoIterator<Item = &'b [u8]>,
    {
        let mut midx_packs: HashSet<Vec<u8>> = HashSet::new();
        for name in self.pack_names() {
            midx_packs.insert(normalize_pack_name(name));
        }

        let mut missing_total = 0usize;
        let mut missing_names = Vec::new();

        for pack_name in actual_packs {
            let normalized = normalize_pack_name(pack_name);
            if !midx_packs.contains(&normalized) {
                missing_total += 1;
                if missing_names.len() < MidxError::missing_packs_limit() {
                    missing_names.push(String::from_utf8_lossy(pack_name).into_owned());
                }
            }
        }

        if missing_total > 0 {
            return Err(MidxError::midx_incomplete(missing_total, missing_names));
        }

        Ok(())
    }

    /// Finds an OID in the MIDX, returning its index if present.
    ///
    /// # Errors
    /// Returns `InputOidLengthMismatch` if the OID length doesn't match the
    /// configured hash format.
    pub fn find_oid(&self, oid: &OidBytes) -> Result<Option<u32>, MidxError> {
        if oid.len() != self.oid_len() {
            return Err(MidxError::InputOidLengthMismatch {
                got: oid.len(),
                expected: self.oid_len(),
            });
        }

        let bytes = oid.as_slice();
        let first = bytes[0];
        let bucket_end = self.fanout(first);
        let bucket_start = if first == 0 {
            0
        } else {
            self.fanout(first - 1)
        };

        let mut lo = bucket_start;
        let mut hi = bucket_end;
        while lo < hi {
            let mid = lo + ((hi - lo) / 2);
            let mid_oid = self.oid_at(mid);
            match bytes.cmp(mid_oid) {
                std::cmp::Ordering::Less => hi = mid,
                std::cmp::Ordering::Greater => lo = mid + 1,
                std::cmp::Ordering::Equal => return Ok(Some(mid)),
            }
        }

        Ok(None)
    }

    /// Finds a sorted OID using a streaming cursor.
    ///
    /// The cursor is advanced monotonically and assumes inputs are strictly
    /// increasing. This enables a merge-join style mapping that avoids a
    /// full binary search per OID.
    ///
    /// If the input OID moves to a new fanout bucket, the cursor is clamped
    /// to that bucket's range.
    pub fn find_oid_sorted(
        &self,
        cursor: &mut MidxCursor,
        oid: &OidBytes,
    ) -> Result<Option<u32>, MidxError> {
        if oid.len() != self.oid_len() {
            return Err(MidxError::InputOidLengthMismatch {
                got: oid.len(),
                expected: self.oid_len(),
            });
        }

        let bytes = oid.as_slice();
        let first = bytes[0];
        if cursor.bucket_first != Some(first) {
            let (start, end) = self.bucket_range(first);
            cursor.bucket_first = Some(first);
            cursor.bucket_end = end;
            if cursor.next_idx < start {
                cursor.next_idx = start;
            } else if cursor.next_idx > end {
                cursor.next_idx = end;
            }
        }

        Ok(self.seek_oid_from(bytes, &mut cursor.next_idx, cursor.bucket_end))
    }

    #[inline]
    fn bucket_range(&self, first_byte: u8) -> (u32, u32) {
        let end = self.fanout(first_byte);
        let start = if first_byte == 0 {
            0
        } else {
            self.fanout(first_byte - 1)
        };
        (start, end)
    }

    fn seek_oid_from(&self, target: &[u8], cursor: &mut u32, bucket_end: u32) -> Option<u32> {
        // Galloping search from the cursor, then binary search within range.
        if *cursor >= bucket_end {
            return None;
        }

        let idx = *cursor;
        match target.cmp(self.oid_at(idx)) {
            std::cmp::Ordering::Equal => {
                *cursor = idx.saturating_add(1);
                return Some(idx);
            }
            std::cmp::Ordering::Greater => {}
            std::cmp::Ordering::Less => {
                return None;
            }
        }

        let mut lo = idx.saturating_add(1);
        let mut hi = lo;
        let mut step = 1_u32;

        while hi < bucket_end {
            match target.cmp(self.oid_at(hi)) {
                std::cmp::Ordering::Equal => {
                    *cursor = hi.saturating_add(1);
                    return Some(hi);
                }
                std::cmp::Ordering::Greater => {
                    lo = hi.saturating_add(1);
                    step = step.saturating_mul(2);
                    hi = hi.saturating_add(step);
                }
                std::cmp::Ordering::Less => break,
            }
        }

        if hi > bucket_end {
            hi = bucket_end;
        }
        if lo >= hi {
            *cursor = lo.min(bucket_end);
            return None;
        }

        let mut left = lo;
        let mut right = hi;
        while left < right {
            let mid = left + ((right - left) / 2);
            match target.cmp(self.oid_at(mid)) {
                std::cmp::Ordering::Less => right = mid,
                std::cmp::Ordering::Greater => left = mid + 1,
                std::cmp::Ordering::Equal => {
                    *cursor = mid.saturating_add(1);
                    return Some(mid);
                }
            }
        }

        *cursor = left.min(bucket_end);
        None
    }

    /// Resolves a LOFF (large offset) indirection to a 64-bit pack offset.
    fn resolve_loff(&self, idx: u32) -> Result<u64, MidxError> {
        let loff = self
            .loff
            .ok_or_else(|| MidxError::corrupt("LOFF indirection but no LOFF"))?;

        let loff_count = (loff.len() / 8) as u32;
        if idx >= loff_count {
            return Err(MidxError::LoffIndexOutOfBounds {
                index: idx,
                count: loff_count,
            });
        }

        let entry_start = idx as usize * 8;
        let offset = u64::from_be_bytes([
            loff[entry_start],
            loff[entry_start + 1],
            loff[entry_start + 2],
            loff[entry_start + 3],
            loff[entry_start + 4],
            loff[entry_start + 5],
            loff[entry_start + 6],
            loff[entry_start + 7],
        ]);

        Ok(offset)
    }

    /// Parses the chunk table, enforcing monotonic offsets and unique IDs.
    ///
    /// The final sentinel entry (all-zero chunk ID) defines the end of the
    /// last chunk.
    fn parse_chunk_table(data: &[u8], chunk_count: u8) -> Result<Vec<ChunkLoc>, MidxError> {
        let chunk_table_start = MIDX_HEADER_SIZE;
        let table_entries = chunk_count as usize + 1;
        let chunk_table_end = chunk_table_start
            .checked_add(table_entries * CHUNK_ENTRY_SIZE)
            .ok_or_else(|| MidxError::corrupt("chunk table size overflow"))?;

        if chunk_table_end > data.len() {
            return Err(MidxError::corrupt("chunk table extends past file"));
        }

        let mut chunks = Vec::with_capacity(chunk_count as usize);
        let mut prev_offset = chunk_table_end as u64;

        for i in 0..table_entries {
            let entry_start = chunk_table_start + i * CHUNK_ENTRY_SIZE;
            let entry = &data[entry_start..entry_start + CHUNK_ENTRY_SIZE];

            let id: [u8; 4] = [entry[0], entry[1], entry[2], entry[3]];
            let offset = u64::from_be_bytes([
                entry[4], entry[5], entry[6], entry[7], entry[8], entry[9], entry[10], entry[11],
            ]);

            if i < chunk_count as usize {
                if offset > data.len() as u64 {
                    return Err(MidxError::corrupt("chunk offset extends past file"));
                }
                if offset < prev_offset {
                    return Err(MidxError::corrupt("chunk offsets not monotonic"));
                }
                if chunks.iter().any(|c: &ChunkLoc| c.id == id) {
                    return Err(MidxError::DuplicateChunk {
                        chunk_id: ChunkId::new(id),
                    });
                }

                chunks.push(ChunkLoc { id, offset, len: 0 });
            }

            if i > 0 {
                let prev_idx = i - 1;
                let prev_off = chunks[prev_idx].offset;
                if offset < prev_off {
                    return Err(MidxError::corrupt("chunk end before start"));
                }
                chunks[prev_idx].len = offset - prev_off;
            }

            prev_offset = offset;
        }

        Ok(chunks)
    }

    fn require_chunk(chunks: &[ChunkLoc], id: [u8; 4]) -> Result<ChunkLoc, MidxError> {
        Self::find_chunk(chunks, id).ok_or(MidxError::MissingChunk {
            chunk_id: ChunkId::new(id),
        })
    }

    fn find_chunk(chunks: &[ChunkLoc], id: [u8; 4]) -> Option<ChunkLoc> {
        chunks.iter().find(|c| c.id == id).copied()
    }

    /// Returns the byte slice for a chunk location.
    fn slice_chunk<'b>(data: &'b [u8], loc: &ChunkLoc) -> Result<&'b [u8], MidxError> {
        let start = loc.offset as usize;
        let end = start
            .checked_add(loc.len as usize)
            .ok_or_else(|| MidxError::corrupt("chunk len overflow"))?;
        if end > data.len() {
            return Err(MidxError::corrupt("chunk extends past file"));
        }
        Ok(&data[start..end])
    }

    /// Validates that the fanout table is non-decreasing and returns total count.
    fn validate_fanout(oidf: &[u8]) -> Result<u32, MidxError> {
        debug_assert!(oidf.len() == FANOUT_SIZE);

        let mut prev = 0u32;
        for i in 0..FANOUT_ENTRIES {
            let off = i * 4;
            let val = u32::from_be_bytes([oidf[off], oidf[off + 1], oidf[off + 2], oidf[off + 3]]);

            if val < prev {
                return Err(MidxError::corrupt("fanout not monotonic"));
            }
            prev = val;
        }

        Ok(prev)
    }

    /// Validates that PNAM contains exactly `pack_count` non-empty names.
    fn validate_pnam(pnam: &[u8], pack_count: u32) -> Result<(), MidxError> {
        let name_count = pnam.split(|&b| b == 0).filter(|s| !s.is_empty()).count() as u32;

        if name_count != pack_count {
            return Err(MidxError::PnamCountMismatch {
                found: name_count,
                expected: pack_count,
            });
        }

        Ok(())
    }
}

/// Normalizes a pack name by stripping `.pack` or `.idx` suffixes.
fn normalize_pack_name(name: &[u8]) -> Vec<u8> {
    if name.ends_with(b".pack") || name.ends_with(b".idx") {
        let mut base = name.to_vec();
        if let Some(idx) = base.iter().rposition(|&b| b == b'.') {
            base.truncate(idx);
        }
        base
    } else {
        name.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::super::midx_test_builder::MidxBuilder;
    use super::*;

    #[test]
    fn parse_minimal_midx() {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-abc123");
        builder.add_object([0x11; 20], 0, 100);
        builder.add_object([0x22; 20], 0, 200);
        let data = builder.build();

        let midx = MidxView::parse(&data, ObjectFormat::Sha1).unwrap();
        assert_eq!(midx.pack_count(), 1);
        assert_eq!(midx.object_count(), 2);
        assert_eq!(midx.oid_len(), 20);
    }

    #[test]
    fn fanout_monotonic() {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-abc123");
        builder.add_object([0x00; 20], 0, 100);
        builder.add_object([0x10; 20], 0, 200);
        let data = builder.build();

        let midx = MidxView::parse(&data, ObjectFormat::Sha1).unwrap();
        assert_eq!(midx.fanout(0x00), 1);
        assert_eq!(midx.fanout(0x10), 2);
        assert_eq!(midx.fanout(0xff), 2);
    }

    #[test]
    fn find_oid_hits() {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-abc123");
        builder.add_object([0x11; 20], 0, 100);
        builder.add_object([0x22; 20], 0, 200);
        let data = builder.build();

        let midx = MidxView::parse(&data, ObjectFormat::Sha1).unwrap();
        let oid = OidBytes::sha1([0x22; 20]);
        let idx = midx.find_oid(&oid).unwrap().unwrap();
        let (pack_id, offset) = midx.offset_at(idx).unwrap();
        assert_eq!(pack_id, 0);
        assert_eq!(offset, 200);
    }

    #[test]
    fn find_oid_sorted_matches_find_oid() {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-abc123");
        builder.add_object([0x01; 20], 0, 100);
        builder.add_object([0x10; 20], 0, 200);
        builder.add_object([0x80; 20], 0, 300);
        let data = builder.build();

        let midx = MidxView::parse(&data, ObjectFormat::Sha1).unwrap();

        let mut inputs = vec![
            OidBytes::sha1([0x00; 20]),
            OidBytes::sha1([0x01; 20]),
            OidBytes::sha1([0x05; 20]),
            OidBytes::sha1([0x10; 20]),
            OidBytes::sha1([0x20; 20]),
            OidBytes::sha1([0x80; 20]),
            OidBytes::sha1([0xff; 20]),
        ];
        inputs.sort();

        let mut cursor = MidxCursor::default();
        for oid in inputs {
            let streamed = midx.find_oid_sorted(&mut cursor, &oid).unwrap();
            let binary = midx.find_oid(&oid).unwrap();
            assert_eq!(streamed, binary, "oid {}", oid);
        }
    }

    #[test]
    fn verify_completeness_passes() {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-abc123");
        builder.add_pack(b"pack-def456");
        let data = builder.build();

        let midx = MidxView::parse(&data, ObjectFormat::Sha1).unwrap();
        let actual: Vec<&[u8]> = vec![b"pack-abc123.idx", b"pack-def456.pack"];
        assert!(midx.verify_completeness(actual).is_ok());
    }

    #[test]
    fn verify_completeness_fails_missing() {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-abc123");
        let data = builder.build();

        let midx = MidxView::parse(&data, ObjectFormat::Sha1).unwrap();
        let actual: Vec<&[u8]> = vec![b"pack-abc123", b"pack-xyz789"];
        let result = midx.verify_completeness(actual);
        assert!(matches!(result, Err(MidxError::MidxIncomplete { .. })));
    }

    #[test]
    fn parse_rejects_wrong_oid_len() {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-abc123");
        builder.add_object([0x11; 20], 0, 100);
        let data = builder.build();

        let result = MidxView::parse(&data, ObjectFormat::Sha256);
        assert!(matches!(result, Err(MidxError::OidLengthMismatch { .. })));
    }
}
