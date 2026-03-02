//! Shared test helpers for building synthetic delta instructions and pack
//! entries. Used by both `pack_inflate` and `object_store` test suites.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

use super::object_id::OidBytes;
use super::pack_inflate::ObjectKind;

/// Compress `data` using zlib (flate2).
pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Encode a LEB128 varint used in delta instruction headers.
pub fn push_varint(value: usize, out: &mut Vec<u8>) {
    push_varint_u64(value as u64, out);
}

/// Encode a LEB128 varint from a `u64` value.
pub fn push_varint_u64(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        out.push(b);
        if value == 0 {
            break;
        }
    }
}

/// Build a delta instruction buffer that adds literal bytes.
///
/// The delta header encodes `base_size` and the literal length as the
/// result size, followed by a single add-literal instruction.
pub fn make_add_delta(base_size: usize, literal: &[u8]) -> Vec<u8> {
    assert!(literal.len() <= 127, "add instruction limited to 127 bytes");
    let mut delta = Vec::new();
    push_varint(base_size, &mut delta);
    push_varint(literal.len(), &mut delta);
    // add instruction: cmd byte = literal length (< 0x80)
    delta.push(literal.len() as u8);
    delta.extend_from_slice(literal);
    delta
}

/// Build a delta with a single copy-from-base instruction.
pub fn make_copy_delta(base_size: usize, off: usize, size: usize) -> Vec<u8> {
    let mut delta = Vec::new();
    push_varint(base_size, &mut delta);
    push_varint(size, &mut delta);
    // copy instruction: high bit set, encode offset and size bytes.
    let mut cmd: u8 = 0x80;
    let mut params = Vec::new();
    // Encode offset (little-endian, flagged)
    if (off & 0xff) != 0 || off == 0 {
        cmd |= 0x01;
        params.push(off as u8);
    }
    if (off >> 8) & 0xff != 0 {
        cmd |= 0x02;
        params.push((off >> 8) as u8);
    }
    if (off >> 16) & 0xff != 0 {
        cmd |= 0x04;
        params.push((off >> 16) as u8);
    }
    if (off >> 24) & 0xff != 0 {
        cmd |= 0x08;
        params.push((off >> 24) as u8);
    }
    // Encode size (little-endian, flagged)
    if (size & 0xff) != 0 {
        cmd |= 0x10;
        params.push(size as u8);
    }
    if (size >> 8) & 0xff != 0 {
        cmd |= 0x20;
        params.push((size >> 8) as u8);
    }
    if (size >> 16) & 0xff != 0 {
        cmd |= 0x40;
        params.push((size >> 16) as u8);
    }
    delta.push(cmd);
    delta.extend_from_slice(&params);
    delta
}

/// Build a mixed delta that copies from the base then adds literal bytes.
pub fn make_mixed_delta(
    base_size: usize,
    copy_off: usize,
    copy_size: usize,
    literal: &[u8],
) -> Vec<u8> {
    let result_size = copy_size + literal.len();
    let mut delta = Vec::new();
    push_varint(base_size, &mut delta);
    push_varint(result_size, &mut delta);
    // Copy instruction: offset byte + size byte
    let cmd: u8 = 0x80 | 0x01 | 0x10;
    delta.push(cmd);
    delta.push(copy_off as u8);
    delta.push(copy_size as u8);
    // Add instruction
    delta.push(literal.len() as u8);
    delta.extend_from_slice(literal);
    delta
}

/// Encode a pack entry type/size varint header.
///
/// First byte: bits [6:4] = type, bits [3:0] = low 4 bits of size,
/// bit 7 = continuation. Subsequent bytes: 7 bits of size each.
pub fn encode_entry_header(obj_type: u8, size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = (obj_type << 4) | ((size & 0x0f) as u8);
    let mut remaining = size >> 4;
    if remaining > 0 {
        first |= 0x80;
    }
    out.push(first);
    while remaining > 0 {
        let mut b = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining > 0 {
            b |= 0x80;
        }
        out.push(b);
    }
    out
}

/// Encode an OFS_DELTA negative offset using the inverse of
/// `parse_ofs_base`'s `val = (val + 1) << 7 | (byte & 0x7f)` formula.
pub fn encode_ofs_offset(negative_offset: u64) -> Vec<u8> {
    let mut val = negative_offset;
    let mut out = Vec::new();
    out.push((val & 0x7f) as u8);
    val >>= 7;
    while val > 0 {
        val -= 1;
        out.push(0x80 | (val & 0x7f) as u8);
        val >>= 7;
    }
    out.reverse();
    out
}

/// Encode a LEB128 varint into a new `Vec` (convenience for callers that
/// use `extend_from_slice(&encode_varint(...))` patterns).
pub fn encode_varint(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    push_varint_u64(value, &mut out);
    out
}

/// Encode an OFS_DELTA backward distance. Identical to [`encode_ofs_offset`]
/// but asserts the distance is non-zero, matching the pack format invariant.
pub fn encode_ofs_distance(dist: u64) -> Vec<u8> {
    assert!(dist > 0, "OFS_DELTA distance must be > 0");
    encode_ofs_offset(dist)
}

/// Encode a pack entry header using an [`ObjectKind`] enum instead of a raw
/// type byte.
pub fn encode_entry_header_kind(kind: ObjectKind, size: usize) -> Vec<u8> {
    let obj_type = match kind {
        ObjectKind::Commit => 1u8,
        ObjectKind::Tree => 2u8,
        ObjectKind::Blob => 3u8,
        ObjectKind::Tag => 4u8,
    };
    encode_entry_header(obj_type, size)
}

/// Builder for synthetic pack files containing non-delta, OFS_DELTA, and
/// REF_DELTA entries. Entry offsets are resolved automatically during
/// `build()`.
pub struct SyntheticPackBuilder {
    entries: Vec<Vec<u8>>,
    /// Stores `Some((base_idx, delta_uncompressed_size, compressed_delta))`
    /// for OFS_DELTA entries, `None` for non-delta entries.
    ofs_delta_info: Vec<Option<(usize, usize, Vec<u8>)>>,
    /// Stores `Some((base_oid, delta_uncompressed_size, compressed_delta))`
    /// for REF_DELTA entries, `None` otherwise.
    ref_delta_info: Vec<Option<(OidBytes, usize, Vec<u8>)>>,
}

impl SyntheticPackBuilder {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            ofs_delta_info: Vec::new(),
            ref_delta_info: Vec::new(),
        }
    }

    /// Add a non-delta entry (type 1=commit, 2=tree, 3=blob).
    pub fn add_non_delta(&mut self, obj_type: u8, data: &[u8]) -> usize {
        let idx = self.entries.len();
        let compressed = zlib_compress(data);
        let mut entry = encode_entry_header(obj_type, data.len());
        entry.extend_from_slice(&compressed);
        self.entries.push(entry);
        self.ofs_delta_info.push(None);
        self.ref_delta_info.push(None);
        idx
    }

    /// Add an OFS_DELTA entry pointing at `base_idx`.
    pub fn add_ofs_delta(&mut self, base_idx: usize, delta_data: &[u8]) -> usize {
        let idx = self.entries.len();
        let compressed = zlib_compress(delta_data);
        // Store a placeholder; real bytes are assembled in build().
        self.entries.push(Vec::new());
        self.ofs_delta_info
            .push(Some((base_idx, delta_data.len(), compressed)));
        self.ref_delta_info.push(None);
        idx
    }

    /// Add a REF_DELTA entry referencing `base_oid`.
    pub fn add_ref_delta(&mut self, base_oid: OidBytes, delta_data: &[u8]) -> usize {
        let idx = self.entries.len();
        let compressed = zlib_compress(delta_data);
        self.entries.push(Vec::new()); // placeholder
        self.ofs_delta_info.push(None);
        self.ref_delta_info
            .push(Some((base_oid, delta_data.len(), compressed)));
        idx
    }

    /// Assemble the pack bytes and return `(pack_bytes, entry_offsets)`.
    pub fn build(&self) -> (Vec<u8>, Vec<u64>) {
        let pack_header_size: u64 = 12;

        // Iteratively compute offsets (converges in 2-3 passes because
        // OFS offset encoding length depends on the offset value itself).
        let mut offsets = vec![0u64; self.entries.len()];
        for _ in 0..3 {
            let mut current_offset = pack_header_size;
            for (i, entry) in self.entries.iter().enumerate() {
                offsets[i] = current_offset;
                if let Some((base_idx, delta_size, ref compressed)) = self.ofs_delta_info[i] {
                    let base_off = offsets[base_idx];
                    let negative_offset = current_offset - base_off;
                    let header = encode_entry_header(6, delta_size);
                    let ofs_bytes = encode_ofs_offset(negative_offset);
                    current_offset +=
                        header.len() as u64 + ofs_bytes.len() as u64 + compressed.len() as u64;
                } else if let Some((ref base_oid, delta_size, ref compressed)) =
                    self.ref_delta_info[i]
                {
                    let header = encode_entry_header(7, delta_size);
                    current_offset +=
                        header.len() as u64 + base_oid.len() as u64 + compressed.len() as u64;
                } else {
                    current_offset += entry.len() as u64;
                }
            }
        }

        // Assemble the actual pack bytes.
        let obj_count = self.entries.len() as u32;
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&obj_count.to_be_bytes());

        for (i, entry) in self.entries.iter().enumerate() {
            let actual_offset = pack.len() as u64;
            assert_eq!(actual_offset, offsets[i], "offset mismatch for entry {i}");

            if let Some((base_idx, delta_size, ref compressed)) = self.ofs_delta_info[i] {
                let base_off = offsets[base_idx];
                let negative_offset = actual_offset - base_off;
                let header = encode_entry_header(6, delta_size);
                let ofs_bytes = encode_ofs_offset(negative_offset);
                pack.extend_from_slice(&header);
                pack.extend_from_slice(&ofs_bytes);
                pack.extend_from_slice(compressed);
            } else if let Some((ref base_oid, delta_size, ref compressed)) = self.ref_delta_info[i]
            {
                let header = encode_entry_header(7, delta_size);
                pack.extend_from_slice(&header);
                pack.extend_from_slice(base_oid.as_slice());
                pack.extend_from_slice(compressed);
            } else {
                pack.extend_from_slice(entry);
            }
        }

        // Trailing SHA-1 hash (zeros for tests).
        pack.extend_from_slice(&[0u8; 20]);

        (pack, offsets)
    }
}
