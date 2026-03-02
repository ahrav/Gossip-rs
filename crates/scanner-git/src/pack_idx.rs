//! Zero-copy parser for Git pack index (`.idx`) v2 files.
//!
//! This module provides efficient parsing of pack index files used for
//! locating objects within Git pack files. The parser is zero-copy: all
//! slices reference the original byte buffer, which must outlive the view.
//!
//! # Scope
//! - Supports pack index version 2 only.
//! - Validates header, fanout monotonicity, and table sizes.
//! - Does **not** validate checksums (pack or index).
//! - Ignores CRC table contents; offsets are trusted after bounds checks.
//!
//! # Complexity
//! - `object_count()` is O(1) from cached fanout[255].
//! - `oid_at()` is O(1) slice into OID table.
//! - `offset_at()` is O(1), may follow large offset indirection.
//! - `iter_oids()` is O(N) sequential iteration (ideal for k-way merge).

use std::fmt;

use super::object_id::ObjectFormat;

/// Pack index magic bytes for v2 format.
const IDX_MAGIC: [u8; 4] = [0xff, b't', b'O', b'c'];
/// Pack index version 2 (only supported version).
const IDX_VERSION: u32 = 2;
/// Header size (8 bytes: 4 magic + 4 version).
const IDX_HEADER_SIZE: usize = 8;
/// Fanout table entries.
const FANOUT_ENTRIES: usize = 256;
/// Fanout table size in bytes.
const FANOUT_SIZE: usize = FANOUT_ENTRIES * 4;
/// MSB mask for detecting large offset indirection.
const LARGE_OFFSET_FLAG: u32 = 0x8000_0000;
/// Maximum index file size (2 GB, conservative limit).
const MAX_IDX_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Errors from pack index parsing.
#[derive(Debug)]
#[non_exhaustive]
pub enum IdxError {
    /// Index file is corrupt or malformed.
    Corrupt { detail: &'static str },
    /// Index version is not supported.
    UnsupportedVersion { version: u32 },
    /// Index file exceeds size limit.
    TooLarge { size: u64, max: u64 },
    /// Index hash version doesn't match expected format.
    FormatMismatch {
        expected: ObjectFormat,
        actual_oid_len: usize,
    },
    /// Large offset index out of bounds.
    LargeOffsetOutOfBounds { index: u32, count: u32 },
    /// Fanout-derived object count inconsistent with computed count from section sizes.
    ObjectCountMismatch {
        fanout_count: u32,
        computed_count: u32,
    },
}

impl IdxError {
    /// Constructs a corruption error with a static detail string.
    #[inline]
    pub const fn corrupt(detail: &'static str) -> Self {
        Self::Corrupt { detail }
    }
}

impl fmt::Display for IdxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt { detail } => write!(f, "corrupt pack index: {detail}"),
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported pack index version: {version} (expected 2)")
            }
            Self::TooLarge { size, max } => {
                write!(f, "pack index too large: {size} bytes (max: {max})")
            }
            Self::FormatMismatch {
                expected,
                actual_oid_len,
            } => write!(
                f,
                "pack index OID length mismatch: expected {} bytes, computed {actual_oid_len}",
                expected.oid_len()
            ),
            Self::LargeOffsetOutOfBounds { index, count } => {
                write!(f, "large offset index out of bounds: {index} >= {count}")
            }
            Self::ObjectCountMismatch {
                fanout_count,
                computed_count,
            } => write!(
                f,
                "object count mismatch: fanout says {fanout_count}, computed {computed_count}"
            ),
        }
    }
}

impl std::error::Error for IdxError {}

/// Zero-copy view over a pack index v2 file.
///
/// # Layout (v2 format)
/// ```text
/// +----------------+
/// | Magic (4B)     |  0xff 't' 'O' 'c'
/// | Version (4B)   |  Big-endian 2
/// +----------------+
/// | Fanout (1024B) |  256 * u32 BE cumulative counts
/// +----------------+
/// | OID Table      |  N * oid_len bytes (sorted)
/// +----------------+
/// | CRC Table      |  N * 4 bytes
/// +----------------+
/// | Offset Table   |  N * 4 bytes (MSB=1 → large offset)
/// +----------------+
/// | Large Offsets  |  M * 8 bytes (optional)
/// +----------------+
/// | Pack Checksum  |  oid_len bytes
/// | Idx Checksum   |  oid_len bytes
/// +----------------+
/// ```
///
/// # Invariants
/// - All table slices are validated to lie within the file buffer.
/// - `object_count` equals `fanout[255]`.
/// - Fanout values are non-decreasing.
#[derive(Debug, Clone, Copy)]
pub struct IdxView<'a> {
    format: ObjectFormat,
    object_count: u32,
    fanout: &'a [u8],
    oid_table: &'a [u8],
    offset_table: &'a [u8],
    large_offsets: Option<&'a [u8]>,
}

impl<'a> IdxView<'a> {
    /// Parses a pack index v2 file from raw bytes.
    ///
    /// This parser is zero-copy: all returned slices borrow from `data`.
    /// Checksums are not validated.
    /// CRC entries are not inspected; the table is only skipped for layout.
    ///
    /// # Errors
    /// Returns `IdxError` if the file is malformed, has unsupported version,
    /// or doesn't match the expected object format.
    pub fn parse(data: &'a [u8], expected_format: ObjectFormat) -> Result<Self, IdxError> {
        if data.len() as u64 > MAX_IDX_SIZE {
            return Err(IdxError::TooLarge {
                size: data.len() as u64,
                max: MAX_IDX_SIZE,
            });
        }

        // Minimum size: header + fanout + 2 checksums
        let min_size = IDX_HEADER_SIZE + FANOUT_SIZE + 2 * expected_format.oid_len() as usize;
        if data.len() < min_size {
            return Err(IdxError::corrupt("file too small"));
        }

        // Validate magic
        if data[0..4] != IDX_MAGIC {
            return Err(IdxError::corrupt("invalid magic"));
        }

        // Validate version
        let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if version != IDX_VERSION {
            return Err(IdxError::UnsupportedVersion { version });
        }

        // Parse fanout
        let fanout_start = IDX_HEADER_SIZE;
        let fanout_end = fanout_start + FANOUT_SIZE;
        let fanout = &data[fanout_start..fanout_end];
        let object_count = Self::validate_fanout(fanout)?;

        let oid_len = expected_format.oid_len() as usize;

        // Calculate expected table sizes
        let oid_table_size = object_count as usize * oid_len;
        let crc_table_size = object_count as usize * 4;
        let offset_table_size = object_count as usize * 4;
        let checksums_size = 2 * oid_len;

        // Minimum size with all tables (no large offsets)
        let min_with_tables = IDX_HEADER_SIZE
            + FANOUT_SIZE
            + oid_table_size
            + crc_table_size
            + offset_table_size
            + checksums_size;

        if data.len() < min_with_tables {
            // Try to compute actual OID length from file size
            let remaining = data.len() - IDX_HEADER_SIZE - FANOUT_SIZE;
            // remaining = N*oid_len + N*4 + N*4 + 2*oid_len + M*8
            // For N objects and M large offsets
            return Err(IdxError::FormatMismatch {
                expected: expected_format,
                actual_oid_len: remaining / object_count.max(1) as usize,
            });
        }

        // Slice tables
        let oid_table_start = fanout_end;
        let oid_table_end = oid_table_start + oid_table_size;
        let oid_table = &data[oid_table_start..oid_table_end];

        // Skip CRC table
        let crc_table_end = oid_table_end + crc_table_size;

        let offset_table_start = crc_table_end;
        let offset_table_end = offset_table_start + offset_table_size;
        let offset_table = &data[offset_table_start..offset_table_end];

        // Large offsets are between offset table and checksums
        let large_offsets_start = offset_table_end;
        let large_offsets_end = data.len() - checksums_size;

        let large_offsets = if large_offsets_end > large_offsets_start {
            let loff = &data[large_offsets_start..large_offsets_end];
            if !loff.len().is_multiple_of(8) {
                return Err(IdxError::corrupt(
                    "large offset table not multiple of 8 bytes",
                ));
            }
            Some(loff)
        } else {
            None
        };

        Ok(Self {
            format: expected_format,
            object_count,
            fanout,
            oid_table,
            offset_table,
            large_offsets,
        })
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

    /// Returns the object format.
    #[inline]
    pub const fn format(&self) -> ObjectFormat {
        self.format
    }

    /// Returns the fanout value for a first-byte value.
    ///
    /// This value is the upper bound (exclusive) of the bucket for that
    /// first byte in the OID list.
    #[inline]
    pub fn fanout(&self, first_byte: u8) -> u32 {
        let off = first_byte as usize * 4;
        u32::from_be_bytes([
            self.fanout[off],
            self.fanout[off + 1],
            self.fanout[off + 2],
            self.fanout[off + 3],
        ])
    }

    /// Returns the OID bytes at the given index.
    ///
    /// # Panics
    /// Panics if `idx` is out of range (debug_assert on index; slice bounds in all builds).
    #[inline]
    pub fn oid_at(&self, idx: u32) -> &[u8] {
        debug_assert!(idx < self.object_count, "OID index out of bounds");
        let oid_len = self.oid_len() as usize;
        let start = idx as usize * oid_len;
        &self.oid_table[start..start + oid_len]
    }

    /// Returns the pack offset for the object at the given index.
    ///
    /// For large offsets (>2GB), resolves indirection through the large
    /// offset table. Offsets are raw pack offsets (not validated).
    ///
    /// # Errors
    /// Returns `LargeOffsetOutOfBounds` if the large offset indirection is invalid,
    /// or `Corrupt` if the large offset flag is set but no large offset table exists.
    pub fn offset_at(&self, idx: u32) -> Result<u64, IdxError> {
        debug_assert!(idx < self.object_count, "offset index out of bounds");

        let entry_start = idx as usize * 4;
        let offset_raw = u32::from_be_bytes([
            self.offset_table[entry_start],
            self.offset_table[entry_start + 1],
            self.offset_table[entry_start + 2],
            self.offset_table[entry_start + 3],
        ]);

        if offset_raw & LARGE_OFFSET_FLAG != 0 {
            let loff_idx = offset_raw & !LARGE_OFFSET_FLAG;
            self.resolve_large_offset(loff_idx)
        } else {
            Ok(offset_raw as u64)
        }
    }

    /// Returns an iterator over (OID bytes, index) pairs in sorted order.
    ///
    /// This is the primary interface for k-way merge: OIDs are already
    /// sorted within each pack index.
    #[inline]
    pub fn iter_oids(&self) -> IdxOidIter<'a> {
        IdxOidIter {
            oid_table: self.oid_table,
            oid_len: self.oid_len() as usize,
            current: 0,
            count: self.object_count,
        }
    }

    /// Resolves a large offset indirection to a 64-bit pack offset.
    ///
    /// The large-offset table is a packed array of big-endian u64 offsets.
    fn resolve_large_offset(&self, idx: u32) -> Result<u64, IdxError> {
        let loff = self
            .large_offsets
            .ok_or_else(|| IdxError::corrupt("large offset flag but no large offset table"))?;

        let loff_count = (loff.len() / 8) as u32;
        if idx >= loff_count {
            return Err(IdxError::LargeOffsetOutOfBounds {
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

    /// Validates that the fanout table is non-decreasing and returns total count.
    ///
    /// The total object count is the final fanout entry (`fanout[255]`).
    fn validate_fanout(fanout: &[u8]) -> Result<u32, IdxError> {
        debug_assert!(fanout.len() == FANOUT_SIZE);

        let mut prev = 0u32;
        for i in 0..FANOUT_ENTRIES {
            let off = i * 4;
            let val = u32::from_be_bytes([
                fanout[off],
                fanout[off + 1],
                fanout[off + 2],
                fanout[off + 3],
            ]);

            if val < prev {
                return Err(IdxError::corrupt("fanout not monotonic"));
            }
            prev = val;
        }

        Ok(prev)
    }
}

/// Iterator over OIDs in a pack index.
///
/// Yields `(oid_bytes, index)` tuples in lexicographic order (pre-sorted by Git).
#[derive(Debug, Clone)]
pub struct IdxOidIter<'a> {
    oid_table: &'a [u8],
    oid_len: usize,
    current: u32,
    count: u32,
}

impl<'a> Iterator for IdxOidIter<'a> {
    /// Yields (oid_bytes, index_in_pack).
    type Item = (&'a [u8], u32);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.count {
            return None;
        }

        let idx = self.current;
        let start = idx as usize * self.oid_len;
        let oid = &self.oid_table[start..start + self.oid_len];
        self.current += 1;

        Some((oid, idx))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.count - self.current) as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for IdxOidIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a minimal pack index v2 file.
    struct IdxBuilder {
        format: ObjectFormat,
        objects: Vec<([u8; 32], u64)>, // (oid, offset)
    }

    impl IdxBuilder {
        fn new(format: ObjectFormat) -> Self {
            Self {
                format,
                objects: Vec::new(),
            }
        }

        fn add_object(&mut self, oid: &[u8], offset: u64) {
            let mut storage = [0u8; 32];
            let len = self.format.oid_len() as usize;
            storage[..len].copy_from_slice(&oid[..len]);
            self.objects.push((storage, offset));
        }

        fn build(&self) -> Vec<u8> {
            let oid_len = self.format.oid_len() as usize;

            // Sort objects by OID
            let mut objects = self.objects.clone();
            objects.sort_by(|a, b| a.0[..oid_len].cmp(&b.0[..oid_len]));

            let n = objects.len();

            // Build fanout
            let mut fanout = vec![0u8; FANOUT_SIZE];
            let mut counts = [0u32; 256];
            for (oid, _) in &objects {
                counts[oid[0] as usize] += 1;
            }
            let mut running = 0u32;
            for (i, count) in counts.iter().enumerate() {
                running += count;
                let off = i * 4;
                fanout[off..off + 4].copy_from_slice(&running.to_be_bytes());
            }

            // Build OID table
            let mut oid_table = Vec::with_capacity(n * oid_len);
            for (oid, _) in &objects {
                oid_table.extend_from_slice(&oid[..oid_len]);
            }

            // Build CRC table (zeros)
            let crc_table = vec![0u8; n * 4];

            // Separate small and large offsets
            let mut offset_table = Vec::with_capacity(n * 4);
            let mut large_offsets = Vec::new();

            for (_, offset) in &objects {
                if *offset >= LARGE_OFFSET_FLAG as u64 {
                    let loff_idx = (large_offsets.len() / 8) as u32;
                    offset_table.extend_from_slice(&(LARGE_OFFSET_FLAG | loff_idx).to_be_bytes());
                    large_offsets.extend_from_slice(&offset.to_be_bytes());
                } else {
                    offset_table.extend_from_slice(&(*offset as u32).to_be_bytes());
                }
            }

            // Build checksums (zeros for test)
            let checksums = vec![0u8; 2 * oid_len];

            // Assemble file
            let mut out = Vec::new();
            out.extend_from_slice(&IDX_MAGIC);
            out.extend_from_slice(&IDX_VERSION.to_be_bytes());
            out.extend_from_slice(&fanout);
            out.extend_from_slice(&oid_table);
            out.extend_from_slice(&crc_table);
            out.extend_from_slice(&offset_table);
            out.extend_from_slice(&large_offsets);
            out.extend_from_slice(&checksums);

            out
        }
    }

    #[test]
    fn parse_minimal_idx() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha1);
        builder.add_object(&[0x11; 20], 100);
        builder.add_object(&[0x22; 20], 200);
        let data = builder.build();

        let idx = IdxView::parse(&data, ObjectFormat::Sha1).unwrap();
        assert_eq!(idx.object_count(), 2);
        assert_eq!(idx.oid_len(), 20);
    }

    #[test]
    fn fanout_monotonic() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha1);
        builder.add_object(&[0x00; 20], 100);
        builder.add_object(&[0x10; 20], 200);
        let mut oid3 = [0u8; 20];
        oid3[0] = 0x10;
        oid3[1] = 0x01;
        builder.add_object(&oid3, 300);
        let data = builder.build();

        let idx = IdxView::parse(&data, ObjectFormat::Sha1).unwrap();
        assert_eq!(idx.fanout(0x00), 1);
        assert_eq!(idx.fanout(0x10), 3);
        assert_eq!(idx.fanout(0xff), 3);
    }

    #[test]
    fn oid_at_returns_correct_slice() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha1);
        let oid1 = [0x11; 20];
        let oid2 = [0x22; 20];
        builder.add_object(&oid1, 100);
        builder.add_object(&oid2, 200);
        let data = builder.build();

        let idx = IdxView::parse(&data, ObjectFormat::Sha1).unwrap();
        assert_eq!(idx.oid_at(0), &oid1[..]);
        assert_eq!(idx.oid_at(1), &oid2[..]);
    }

    #[test]
    fn offset_at_small_offset() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha1);
        builder.add_object(&[0x11; 20], 12345);
        let data = builder.build();

        let idx = IdxView::parse(&data, ObjectFormat::Sha1).unwrap();
        assert_eq!(idx.offset_at(0).unwrap(), 12345);
    }

    #[test]
    fn offset_at_large_offset() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha1);
        let large_offset = 0x1_0000_0000_u64; // 4GB
        builder.add_object(&[0x11; 20], large_offset);
        let data = builder.build();

        let idx = IdxView::parse(&data, ObjectFormat::Sha1).unwrap();
        assert_eq!(idx.offset_at(0).unwrap(), large_offset);
    }

    #[test]
    fn iter_oids_sorted() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha1);
        // Add in reverse order
        builder.add_object(&[0x33; 20], 300);
        builder.add_object(&[0x11; 20], 100);
        builder.add_object(&[0x22; 20], 200);
        let data = builder.build();

        let idx = IdxView::parse(&data, ObjectFormat::Sha1).unwrap();
        let oids: Vec<_> = idx.iter_oids().collect();

        assert_eq!(oids.len(), 3);
        // Should be sorted
        assert_eq!(oids[0].0, &[0x11; 20][..]);
        assert_eq!(oids[1].0, &[0x22; 20][..]);
        assert_eq!(oids[2].0, &[0x33; 20][..]);
        // Index should be in sorted order
        assert_eq!(oids[0].1, 0);
        assert_eq!(oids[1].1, 1);
        assert_eq!(oids[2].1, 2);
    }

    #[test]
    fn iter_oids_exact_size() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha1);
        builder.add_object(&[0x11; 20], 100);
        builder.add_object(&[0x22; 20], 200);
        builder.add_object(&[0x33; 20], 300);
        let data = builder.build();

        let idx = IdxView::parse(&data, ObjectFormat::Sha1).unwrap();
        let iter = idx.iter_oids();

        assert_eq!(iter.len(), 3);
    }

    #[test]
    fn parse_sha256_format() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha256);
        builder.add_object(&[0x11; 32], 100);
        builder.add_object(&[0x22; 32], 200);
        let data = builder.build();

        let idx = IdxView::parse(&data, ObjectFormat::Sha256).unwrap();
        assert_eq!(idx.object_count(), 2);
        assert_eq!(idx.oid_len(), 32);
    }

    #[test]
    fn parse_rejects_wrong_format() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha1);
        builder.add_object(&[0x11; 20], 100);
        let data = builder.build();

        // Try to parse SHA-1 index as SHA-256
        let result = IdxView::parse(&data, ObjectFormat::Sha256);
        assert!(matches!(result, Err(IdxError::FormatMismatch { .. })));
    }

    #[test]
    fn parse_rejects_invalid_magic() {
        let mut data = vec![0u8; 2048];
        data[0..4].copy_from_slice(b"PACK"); // Wrong magic

        let result = IdxView::parse(&data, ObjectFormat::Sha1);
        assert!(matches!(result, Err(IdxError::Corrupt { .. })));
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let mut data = vec![0u8; 2048];
        data[0..4].copy_from_slice(&IDX_MAGIC);
        data[4..8].copy_from_slice(&1_u32.to_be_bytes()); // Version 1

        let result = IdxView::parse(&data, ObjectFormat::Sha1);
        assert!(matches!(
            result,
            Err(IdxError::UnsupportedVersion { version: 1 })
        ));
    }

    #[test]
    fn parse_empty_index() {
        // Empty index (0 objects)
        let mut out = Vec::new();
        out.extend_from_slice(&IDX_MAGIC);
        out.extend_from_slice(&IDX_VERSION.to_be_bytes());
        out.extend_from_slice(&[0u8; FANOUT_SIZE]); // All zeros
        out.extend_from_slice(&[0u8; 40]); // Two SHA-1 checksums

        let idx = IdxView::parse(&out, ObjectFormat::Sha1).unwrap();
        assert_eq!(idx.object_count(), 0);
        assert_eq!(idx.iter_oids().count(), 0);
    }

    #[test]
    fn large_offset_out_of_bounds() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha1);
        builder.add_object(&[0x11; 20], 0x1_0000_0000); // Large offset
        let mut data = builder.build();

        // Corrupt the large offset table by truncating it
        let checksums_size = 40;
        let truncate_to = data.len() - checksums_size - 8; // Remove large offset entry
        data.truncate(truncate_to);
        // Add back checksums
        data.extend_from_slice(&[0u8; 40]);

        let idx = IdxView::parse(&data, ObjectFormat::Sha1).unwrap();
        let result = idx.offset_at(0);
        assert!(matches!(result, Err(IdxError::Corrupt { .. })));
    }

    #[test]
    fn multiple_large_offsets() {
        let mut builder = IdxBuilder::new(ObjectFormat::Sha1);
        let large1 = 0x1_0000_0000_u64;
        let large2 = 0x2_0000_0000_u64;
        let large3 = 0x3_0000_0000_u64;
        builder.add_object(&[0x11; 20], large1);
        builder.add_object(&[0x22; 20], large2);
        builder.add_object(&[0x33; 20], large3);
        let data = builder.build();

        let idx = IdxView::parse(&data, ObjectFormat::Sha1).unwrap();
        assert_eq!(idx.offset_at(0).unwrap(), large1);
        assert_eq!(idx.offset_at(1).unwrap(), large2);
        assert_eq!(idx.offset_at(2).unwrap(), large3);
    }
}
