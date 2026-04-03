//! Seen-bitmap delta and RocksDB bitmap encoding helpers.
//!
//! `SeenBitmapDelta` is the finalize-time payload: it carries the sorted OIDs
//! that were scanned during the current finalize call. The persisted on-disk
//! format is `RoaringSeenBitmap`, which stores the scope's sorted OID index and
//! a Roaring bitmap over that index.

use super::errors::SpillError;
use super::object_id::OidBytes;
use super::seen_store::SeenBlobStore;
use roaring::RoaringBitmap;

const DELTA_MAGIC: [u8; 4] = *b"RSBD";
const BITMAP_MAGIC: [u8; 4] = *b"RSBM";
/// Hard ceiling on the roaring bitmap payload size accepted during
/// deserialization. 512 MiB is well beyond any realistic working set and
/// prevents unbounded memory allocation from a corrupt or malicious payload.
const MAX_BITMAP_BYTES: usize = 512 * 1024 * 1024;

/// Errors returned while encoding or decoding seen-bitmap payloads.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SeenBitmapError {
    /// Input used mixed SHA-1 and SHA-256 object IDs in a single payload.
    #[error("seen-bitmap input used mixed OID lengths")]
    MixedOidLengths,
    /// The payload used an OID length other than Git's 20-byte SHA-1 or
    /// 32-byte SHA-256 object IDs.
    #[error("invalid seen-bitmap OID length: {0}")]
    InvalidOidLength(u8),
    /// The serialized payload ended before all fields were present.
    #[error("truncated seen-bitmap payload")]
    Truncated,
    /// The serialized payload had an unexpected magic header.
    #[error("invalid seen-bitmap magic header")]
    InvalidMagic,
    /// The serialized payload contained duplicate or unsorted OIDs.
    #[error("seen-bitmap OIDs must be strictly sorted and unique")]
    NonCanonicalOids,
    /// The payload tried to index more OIDs than the u32-backed bitmap can
    /// address.
    #[error("seen-bitmap OID count exceeds u32::MAX: {0}")]
    TooManyOids(usize),
    /// The payload contained trailing bytes after the last expected field.
    #[error("seen-bitmap payload length mismatch")]
    LengthMismatch,
    /// The persisted roaring bitmap could not be decoded.
    #[error("invalid roaring bitmap payload: {0}")]
    InvalidBitmap(String),
    /// The roaring bitmap could not be serialized.
    #[error("bitmap serialization failed: {0}")]
    SerializationFailed(String),
    /// The serialized bitmap payload exceeds the maximum allowed size.
    #[error("bitmap payload too large: {size} bytes (max {max})")]
    BitmapTooLarge {
        /// Actual size of the bitmap payload in bytes.
        size: usize,
        /// Maximum allowed size in bytes.
        max: usize,
    },
}

fn validate_oid_len(oid_len: u8) -> Result<(), SeenBitmapError> {
    if oid_len == OidBytes::SHA1_LEN || oid_len == OidBytes::SHA256_LEN {
        Ok(())
    } else {
        Err(SeenBitmapError::InvalidOidLength(oid_len))
    }
}

fn u32_len(len: usize) -> Result<u32, SeenBitmapError> {
    u32::try_from(len).map_err(|_| SeenBitmapError::TooManyOids(len))
}

fn canonicalize_oids(oids: &[OidBytes]) -> Result<(u8, Vec<OidBytes>), SeenBitmapError> {
    let Some(first) = oids.first() else {
        // At least one OID is required to determine the object format
        // (SHA-1 vs SHA-256). Callers must filter empty inputs upstream.
        return Err(SeenBitmapError::Truncated);
    };

    let oid_len = first.len();
    validate_oid_len(oid_len)?;

    let mut out = Vec::with_capacity(oids.len());
    for oid in oids {
        if oid.len() != oid_len {
            return Err(SeenBitmapError::MixedOidLengths);
        }
        out.push(*oid);
    }
    out.sort_unstable();
    out.dedup();
    let _ = u32_len(out.len())?;
    Ok((oid_len, out))
}

fn oids_are_canonical(oids: &[OidBytes]) -> bool {
    oids.windows(2).all(|pair| pair[0] < pair[1])
}

/// Finalize-time delta payload for the `sb\0` namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeenBitmapDelta {
    oid_len: u8,
    oids: Vec<OidBytes>,
}

impl SeenBitmapDelta {
    /// Builds a canonical delta from the provided OIDs.
    ///
    /// The input must contain at least one OID so the object format (SHA-1
    /// vs SHA-256) can be inferred. Returns `SeenBitmapError::Truncated`
    /// when `oids` is empty. Duplicates and unsorted entries are accepted
    /// and canonicalized internally.
    pub fn from_oids(oids: &[OidBytes]) -> Result<Self, SeenBitmapError> {
        let (oid_len, oids) = canonicalize_oids(oids)?;
        Ok(Self { oid_len, oids })
    }

    /// Builds a delta from OIDs that are already sorted and unique.
    ///
    /// This avoids the sort/dedup cost of [`from_oids`](Self::from_oids) when
    /// the caller can guarantee canonical ordering. Returns
    /// `SeenBitmapError::NonCanonicalOids` if the invariant is violated.
    /// Like `from_oids`, at least one OID is required to infer the object
    /// format.
    pub fn from_canonical_oids(oids: Vec<OidBytes>) -> Result<Self, SeenBitmapError> {
        let Some(first) = oids.first() else {
            return Err(SeenBitmapError::Truncated);
        };
        let oid_len = first.len();
        validate_oid_len(oid_len)?;
        for oid in &oids {
            if oid.len() != oid_len {
                return Err(SeenBitmapError::MixedOidLengths);
            }
        }
        if !oids_are_canonical(&oids) {
            return Err(SeenBitmapError::NonCanonicalOids);
        }
        let _ = u32_len(oids.len())?;
        Ok(Self { oid_len, oids })
    }

    /// Returns the OID length carried by this delta.
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }

    /// Returns the sorted OIDs stored in this delta.
    #[must_use]
    pub fn oids(&self) -> &[OidBytes] {
        &self.oids
    }

    /// Returns the number of OIDs stored in this delta.
    #[must_use]
    pub fn len(&self) -> usize {
        self.oids.len()
    }

    /// Returns true when the delta contains no OIDs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.oids.is_empty()
    }

    /// Returns the serialized byte length for this delta.
    #[must_use]
    pub fn serialized_size(&self) -> usize {
        4 + 1 + 4 + self.oids.len() * self.oid_len as usize
    }

    /// Serializes the delta into a deterministic byte sequence.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.serialized_size());
        out.extend_from_slice(&DELTA_MAGIC);
        out.push(self.oid_len);
        let oid_count: u32 = self
            .oids
            .len()
            .try_into()
            .expect("delta OID count validated at construction via u32_len");
        out.extend_from_slice(&oid_count.to_be_bytes());
        for oid in &self.oids {
            debug_assert_eq!(oid.len(), self.oid_len, "delta OID length mismatch");
            out.extend_from_slice(oid.as_slice());
        }
        out
    }

    /// Deserializes a finalize-time delta payload.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, SeenBitmapError> {
        if bytes.len() < 9 {
            return Err(SeenBitmapError::Truncated);
        }
        if bytes[..4] != DELTA_MAGIC {
            return Err(SeenBitmapError::InvalidMagic);
        }

        let oid_len = bytes[4];
        validate_oid_len(oid_len)?;
        let oid_count = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
        let payload_len = oid_count
            .checked_mul(oid_len as usize)
            .ok_or(SeenBitmapError::LengthMismatch)?;
        let expected_len = 9usize
            .checked_add(payload_len)
            .ok_or(SeenBitmapError::LengthMismatch)?;
        if bytes.len() != expected_len {
            return Err(SeenBitmapError::LengthMismatch);
        }

        let mut oids = Vec::with_capacity(oid_count);
        let mut offset = 9;
        for _ in 0..oid_count {
            let next = offset + oid_len as usize;
            let oid = OidBytes::try_from_slice(&bytes[offset..next])
                .ok_or(SeenBitmapError::InvalidOidLength(oid_len))?;
            oids.push(oid);
            offset = next;
        }
        if !oids.is_empty() && !oids_are_canonical(&oids) {
            return Err(SeenBitmapError::NonCanonicalOids);
        }

        Ok(Self { oid_len, oids })
    }
}

fn insert_position(bitmap: &mut RoaringBitmap, pos: usize) -> Result<(), SeenBitmapError> {
    bitmap.insert(u32::try_from(pos).map_err(|_| SeenBitmapError::TooManyOids(pos + 1))?);
    Ok(())
}

fn bitmap_contains(bitmap: &RoaringBitmap, pos: usize) -> bool {
    bitmap.contains(u32::try_from(pos).expect("bitmap position exceeds u32::MAX"))
}

/// Persisted seen bitmap for one `(repo_id, policy_hash)` scope.
#[derive(Clone, Debug, PartialEq)]
pub struct RoaringSeenBitmap {
    oid_len: u8,
    oids: Vec<OidBytes>,
    seen: RoaringBitmap,
}

impl RoaringSeenBitmap {
    /// Creates an empty bitmap for one repository object format.
    #[must_use]
    pub fn new(oid_len: u8) -> Self {
        validate_oid_len(oid_len).expect("RoaringSeenBitmap requires SHA-1 or SHA-256 OIDs");
        Self {
            oid_len,
            oids: Vec::new(),
            seen: RoaringBitmap::new(),
        }
    }

    /// Returns the stored OID length for this scope.
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }

    /// Returns the number of OIDs marked as seen.
    ///
    /// This may be less than [`index_len`](Self::index_len) because the
    /// sorted OID index retains entries from merges even when their seen
    /// bit is unset.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::try_from(self.seen.len()).unwrap_or(usize::MAX)
    }

    /// Returns the total number of OIDs in the sorted index.
    ///
    /// May exceed [`len`](Self::len) because the index grows
    /// monotonically across merges. The difference represents OIDs
    /// known to the index but not yet marked as seen.
    #[must_use]
    pub fn index_len(&self) -> usize {
        self.oids.len()
    }

    /// Returns true when the bitmap tracks no seen OIDs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Returns a slice of all OIDs in the sorted index.
    #[must_use]
    pub fn all_oids(&self) -> &[OidBytes] {
        &self.oids
    }

    /// Returns the serialized byte length for the persisted bitmap payload.
    #[must_use]
    pub fn serialized_size(&self) -> usize {
        4 + 1 + 4 + self.oids.len() * self.oid_len as usize + 4 + self.seen.serialized_size()
    }

    /// Returns true when the OID has already been seen in this scope.
    #[must_use]
    pub fn contains(&self, oid: &OidBytes) -> bool {
        if oid.len() != self.oid_len {
            return false;
        }
        match self.oids.binary_search(oid) {
            Ok(idx) => bitmap_contains(&self.seen, idx),
            Err(_) => false,
        }
    }

    /// Batch membership query preserving the input order.
    ///
    /// Probes each OID independently via binary search. For sorted inputs
    /// prefer [`batch_contains_sorted`](Self::batch_contains_sorted).
    #[must_use]
    pub fn batch_contains(&self, oids: &[OidBytes]) -> Vec<bool> {
        oids.iter().map(|oid| self.contains(oid)).collect()
    }

    /// O(n+m) batch membership query for **sorted** input.
    ///
    /// Walks two pointers over `self.oids` and the probe slice in a single
    /// pass, avoiding the O(n log m) cost of per-element binary search.
    /// The `SeenBlobStore` contract guarantees sorted inputs, so this is
    /// the preferred hot-path implementation.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `oids` is strictly sorted.
    #[must_use]
    pub fn batch_contains_sorted(&self, oids: &[OidBytes]) -> Vec<bool> {
        debug_assert!(
            oids.windows(2).all(|pair| pair[0] <= pair[1]),
            "batch_contains_sorted requires non-decreasing (sorted) input"
        );
        let mut result = vec![false; oids.len()];
        let index = &self.oids;
        let index_len = index.len();
        let mut idx = 0usize;
        for (i, oid) in oids.iter().enumerate() {
            if oid.len() != self.oid_len {
                continue;
            }
            // Advance the index pointer past OIDs smaller than the probe.
            while idx < index_len && index[idx] < *oid {
                idx += 1;
            }
            if idx < index_len && index[idx] == *oid {
                result[i] = bitmap_contains(&self.seen, idx);
            }
        }
        result
    }

    /// Inserts a batch of OIDs, growing the index and seen bitmap as needed.
    pub fn insert_batch(&mut self, oids: &[OidBytes]) -> Result<(), SeenBitmapError> {
        if oids.is_empty() {
            return Ok(());
        }
        let delta = SeenBitmapDelta::from_oids(oids)?;
        self.merge_delta(&delta)
    }

    /// Merges another persisted bitmap into this one.
    pub fn merge(&mut self, other: &Self) -> Result<(), SeenBitmapError> {
        if self.oid_len != other.oid_len {
            return Err(SeenBitmapError::MixedOidLengths);
        }
        self.merge_positions(&other.oids, |idx| bitmap_contains(&other.seen, idx))
    }

    pub fn merge_delta(&mut self, delta: &SeenBitmapDelta) -> Result<(), SeenBitmapError> {
        if self.oid_len != delta.oid_len {
            return Err(SeenBitmapError::MixedOidLengths);
        }
        self.merge_positions(delta.oids(), |_| true)
    }

    fn merge_positions<F>(
        &mut self,
        other_oids: &[OidBytes],
        other_contains: F,
    ) -> Result<(), SeenBitmapError>
    where
        F: Fn(usize) -> bool,
    {
        if other_oids.is_empty() {
            return Ok(());
        }
        // Pre-flight: catch usize overflow before allocation. The actual
        // merged count may be smaller due to dedup, so this is a
        // conservative upper bound rather than the authoritative check.
        let _ = self
            .oids
            .len()
            .checked_add(other_oids.len())
            .ok_or(SeenBitmapError::TooManyOids(usize::MAX))?;

        let mut merged_oids = Vec::with_capacity(self.oids.len() + other_oids.len());
        let mut merged_seen = RoaringBitmap::new();
        let mut left = 0usize;
        let mut right = 0usize;

        while left < self.oids.len() && right < other_oids.len() {
            use std::cmp::Ordering::{Equal, Greater, Less};

            let insert_seen = match self.oids[left].cmp(&other_oids[right]) {
                Less => {
                    merged_oids.push(self.oids[left]);
                    let seen = bitmap_contains(&self.seen, left);
                    left += 1;
                    seen
                }
                Greater => {
                    merged_oids.push(other_oids[right]);
                    let seen = other_contains(right);
                    right += 1;
                    seen
                }
                Equal => {
                    merged_oids.push(self.oids[left]);
                    let seen = bitmap_contains(&self.seen, left) || other_contains(right);
                    left += 1;
                    right += 1;
                    seen
                }
            };
            if insert_seen {
                insert_position(&mut merged_seen, merged_oids.len() - 1)?;
            }
        }

        while left < self.oids.len() {
            merged_oids.push(self.oids[left]);
            if bitmap_contains(&self.seen, left) {
                insert_position(&mut merged_seen, merged_oids.len() - 1)?;
            }
            left += 1;
        }

        while right < other_oids.len() {
            merged_oids.push(other_oids[right]);
            if other_contains(right) {
                insert_position(&mut merged_seen, merged_oids.len() - 1)?;
            }
            right += 1;
        }

        // Authoritative check: the deduped merged count is the real value
        // that must fit in u32 for the bitmap to index correctly.
        let _ = u32_len(merged_oids.len())?;

        self.oids = merged_oids;
        self.seen = merged_seen;
        Ok(())
    }

    /// Serializes the persisted bitmap payload.
    pub fn serialize(&self) -> Result<Vec<u8>, SeenBitmapError> {
        let bitmap_len = self.seen.serialized_size();
        // Enforce the same size cap that deserialize() applies so the write
        // path never emits a payload that the read path would reject.
        if bitmap_len > MAX_BITMAP_BYTES {
            return Err(SeenBitmapError::BitmapTooLarge {
                size: bitmap_len,
                max: MAX_BITMAP_BYTES,
            });
        }
        let mut out = Vec::with_capacity(self.serialized_size());
        out.extend_from_slice(&BITMAP_MAGIC);
        out.push(self.oid_len);
        let oid_count: u32 = self
            .oids
            .len()
            .try_into()
            .expect("bitmap OID count validated at construction via u32_len");
        out.extend_from_slice(&oid_count.to_be_bytes());
        for oid in &self.oids {
            debug_assert_eq!(oid.len(), self.oid_len, "bitmap OID length mismatch");
            out.extend_from_slice(oid.as_slice());
        }
        let bitmap_len_u32: u32 = bitmap_len.try_into().map_err(|_| {
            SeenBitmapError::SerializationFailed(format!(
                "roaring bitmap serialized size {bitmap_len} exceeds u32::MAX"
            ))
        })?;
        out.extend_from_slice(&bitmap_len_u32.to_be_bytes());
        self.seen
            .serialize_into(&mut out)
            .map_err(|err| SeenBitmapError::SerializationFailed(err.to_string()))?;
        Ok(out)
    }

    /// Deserializes a persisted bitmap payload.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, SeenBitmapError> {
        use std::io::Cursor;

        if bytes.len() < 13 {
            return Err(SeenBitmapError::Truncated);
        }
        if bytes[..4] != BITMAP_MAGIC {
            return Err(SeenBitmapError::InvalidMagic);
        }

        let oid_len = bytes[4];
        validate_oid_len(oid_len)?;
        let oid_count_u32 = u32::from_be_bytes(bytes[5..9].try_into().unwrap());
        let oid_count = oid_count_u32 as usize;
        let oid_bytes_len = oid_count
            .checked_mul(oid_len as usize)
            .ok_or(SeenBitmapError::LengthMismatch)?;
        let bitmap_len_offset = 9usize
            .checked_add(oid_bytes_len)
            .ok_or(SeenBitmapError::LengthMismatch)?;
        if bytes.len() < bitmap_len_offset + 4 {
            return Err(SeenBitmapError::Truncated);
        }
        let bitmap_len = u32::from_be_bytes(
            bytes[bitmap_len_offset..bitmap_len_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        if bitmap_len > MAX_BITMAP_BYTES {
            return Err(SeenBitmapError::BitmapTooLarge {
                size: bitmap_len,
                max: MAX_BITMAP_BYTES,
            });
        }
        let expected_len = bitmap_len_offset
            .checked_add(4)
            .and_then(|n| n.checked_add(bitmap_len))
            .ok_or(SeenBitmapError::LengthMismatch)?;
        if bytes.len() != expected_len {
            return Err(SeenBitmapError::LengthMismatch);
        }

        let mut oids = Vec::with_capacity(oid_count);
        let mut offset = 9;
        for _ in 0..oid_count {
            let next = offset + oid_len as usize;
            let oid = OidBytes::try_from_slice(&bytes[offset..next])
                .ok_or(SeenBitmapError::InvalidOidLength(oid_len))?;
            oids.push(oid);
            offset = next;
        }
        if !oids.is_empty() && !oids_are_canonical(&oids) {
            return Err(SeenBitmapError::NonCanonicalOids);
        }

        let bitmap = RoaringBitmap::deserialize_from(Cursor::new(
            &bytes[bitmap_len_offset + 4..expected_len],
        ))
        .map_err(|err| SeenBitmapError::InvalidBitmap(err.to_string()))?;

        // Reject payloads where the roaring bitmap references positions
        // beyond the OID index. Without this check, a corrupt or malicious
        // payload could inflate `len()` / `is_empty()` and persist phantom
        // bits through round-trip serialization.
        if let Some(max) = bitmap.max() {
            if max >= oid_count_u32 {
                return Err(SeenBitmapError::InvalidBitmap(format!(
                    "bitmap references position {max} but OID index has {oid_count_u32} entries"
                )));
            }
        }

        Ok(Self {
            oid_len,
            oids,
            seen: bitmap,
        })
    }
}

/// In-memory seen store backed by a roaring bitmap scope snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct RoaringSeenStore {
    bitmap: RoaringSeenBitmap,
}

impl RoaringSeenStore {
    /// Builds a store from a persisted bitmap snapshot.
    #[must_use]
    pub fn new(bitmap: RoaringSeenBitmap) -> Self {
        Self { bitmap }
    }

    /// Returns the underlying bitmap snapshot.
    #[must_use]
    pub fn bitmap(&self) -> &RoaringSeenBitmap {
        &self.bitmap
    }

    /// Returns a mutable reference to the underlying bitmap.
    pub fn bitmap_mut(&mut self) -> &mut RoaringSeenBitmap {
        &mut self.bitmap
    }

    /// Consumes the store and returns the underlying bitmap.
    #[must_use]
    pub fn into_bitmap(self) -> RoaringSeenBitmap {
        self.bitmap
    }
}

impl SeenBlobStore for RoaringSeenStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        Ok(self.bitmap.batch_contains_sorted(oids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn sha1(byte: u8) -> OidBytes {
        OidBytes::sha1([byte; 20])
    }

    fn raw_oid_bytes(oids: &[OidBytes]) -> Vec<u8> {
        let mut out = Vec::new();
        for oid in oids {
            out.extend_from_slice(oid.as_slice());
        }
        out
    }

    fn delta_bytes(magic: [u8; 4], oid_len: u8, oid_count: u32, oid_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + oid_bytes.len());
        out.extend_from_slice(&magic);
        out.push(oid_len);
        out.extend_from_slice(&oid_count.to_be_bytes());
        out.extend_from_slice(oid_bytes);
        out
    }

    fn bitmap_bytes(
        magic: [u8; 4],
        oid_len: u8,
        oid_count: u32,
        oid_bytes: &[u8],
        bitmap_len: u32,
        bitmap_bytes: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + oid_bytes.len() + 4 + bitmap_bytes.len());
        out.extend_from_slice(&magic);
        out.push(oid_len);
        out.extend_from_slice(&oid_count.to_be_bytes());
        out.extend_from_slice(oid_bytes);
        out.extend_from_slice(&bitmap_len.to_be_bytes());
        out.extend_from_slice(bitmap_bytes);
        out
    }

    #[test]
    fn seen_bitmap_delta_round_trips() {
        let delta = SeenBitmapDelta::from_oids(&[sha1(0x30), sha1(0x10), sha1(0x30), sha1(0x20)])
            .expect("delta");
        let bytes = delta.serialize();
        let decoded = SeenBitmapDelta::deserialize(&bytes).expect("decode");

        assert_eq!(decoded.oids(), &[sha1(0x10), sha1(0x20), sha1(0x30)]);
    }

    #[test]
    fn seen_bitmap_delta_rejects_empty_input() {
        let err = SeenBitmapDelta::from_oids(&[]).expect_err("empty input must fail");
        assert_eq!(err, SeenBitmapError::Truncated);
    }

    #[test]
    fn seen_bitmap_delta_rejects_mixed_lengths() {
        let err =
            SeenBitmapDelta::from_oids(&[OidBytes::sha1([0x11; 20]), OidBytes::sha256([0x22; 32])])
                .expect_err("mixed lengths must fail");

        assert_eq!(err, SeenBitmapError::MixedOidLengths);
    }

    #[rstest]
    #[case::truncated(vec![0; 8], SeenBitmapError::Truncated)]
    #[case::invalid_magic(
        delta_bytes(*b"BAD!", OidBytes::SHA1_LEN, 0, &[]),
        SeenBitmapError::InvalidMagic
    )]
    #[case::invalid_oid_len(
        delta_bytes(DELTA_MAGIC, 21, 0, &[]),
        SeenBitmapError::InvalidOidLength(21)
    )]
    #[case::length_mismatch(
        delta_bytes(DELTA_MAGIC, OidBytes::SHA1_LEN, 1, &[]),
        SeenBitmapError::LengthMismatch
    )]
    #[case::non_canonical_oids(
        delta_bytes(
            DELTA_MAGIC,
            OidBytes::SHA1_LEN,
            2,
            &raw_oid_bytes(&[sha1(0x20), sha1(0x10)])
        ),
        SeenBitmapError::NonCanonicalOids
    )]
    fn seen_bitmap_delta_deserialize_rejects_invalid_inputs(
        #[case] bytes: Vec<u8>,
        #[case] expected: SeenBitmapError,
    ) {
        let err = SeenBitmapDelta::deserialize(&bytes).expect_err("invalid delta must fail");
        assert_eq!(err, expected);
    }

    #[test]
    fn roaring_bitmap_round_trips() {
        let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        bitmap
            .insert_batch(&[sha1(0x10), sha1(0x20), sha1(0x30)])
            .expect("insert");

        let bytes = bitmap.serialize().expect("serialize");
        let decoded = RoaringSeenBitmap::deserialize(&bytes).expect("decode");
        assert_eq!(decoded, bitmap);
    }

    #[test]
    fn roaring_bitmap_serialization_golden_value() {
        let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        bitmap
            .insert_batch(&[sha1(0x10), sha1(0x20), sha1(0x30)])
            .expect("insert");

        let actual: String = bitmap
            .serialize()
            .expect("serialize")
            .into_iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        // Canonical on-disk encoding: any change here means a storage format
        // migration is needed.
        const EXPECTED: &str =
            "5253424d1400000003101010101010101010101010101010101010101020202020202020202020202020202020202020203030303030303030303030303030303030303030000000163a300000010000000000020010000000000001000200";
        assert_eq!(actual, EXPECTED, "roaring bitmap serialization changed");
    }

    #[test]
    fn roaring_bitmap_empty_query_is_all_false() {
        let bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        assert_eq!(
            bitmap.batch_contains(&[sha1(0x11), sha1(0x22)]),
            vec![false, false]
        );
    }

    #[test]
    fn roaring_bitmap_batch_contains_sorted_matches_unsorted() {
        let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        bitmap
            .insert_batch(&[sha1(0x10), sha1(0x30), sha1(0x50)])
            .expect("insert");

        let mut probes = vec![sha1(0x10), sha1(0x20), sha1(0x30), sha1(0x40), sha1(0x50)];
        probes.sort_unstable();

        let sorted_result = bitmap.batch_contains_sorted(&probes);
        let unsorted_result = bitmap.batch_contains(&probes);
        assert_eq!(sorted_result, unsorted_result);
        assert_eq!(sorted_result, vec![true, false, true, false, true]);
    }

    #[test]
    fn roaring_bitmap_merge_preserves_membership() {
        let mut left = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        left.insert_batch(&[sha1(0x10), sha1(0x30)]).expect("left");

        let mut right = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        right
            .insert_batch(&[sha1(0x20), sha1(0x30)])
            .expect("right");

        left.merge(&right).expect("merge");

        assert_eq!(
            left.batch_contains(&[sha1(0x10), sha1(0x20), sha1(0x30), sha1(0x40)]),
            vec![true, true, true, false]
        );
    }

    #[rstest]
    #[case::truncated(vec![0; 12], SeenBitmapError::Truncated)]
    #[case::invalid_magic(
        bitmap_bytes(*b"BAD!", OidBytes::SHA1_LEN, 0, &[], 0, &[]),
        SeenBitmapError::InvalidMagic
    )]
    #[case::invalid_oid_len(
        bitmap_bytes(BITMAP_MAGIC, 21, 0, &[], 0, &[]),
        SeenBitmapError::InvalidOidLength(21)
    )]
    #[case::length_mismatch(
        bitmap_bytes(BITMAP_MAGIC, OidBytes::SHA1_LEN, 1, sha1(0x10).as_slice(), 1, &[]),
        SeenBitmapError::LengthMismatch
    )]
    #[case::non_canonical_oids(
        bitmap_bytes(
            BITMAP_MAGIC,
            OidBytes::SHA1_LEN,
            2,
            &raw_oid_bytes(&[sha1(0x20), sha1(0x10)]),
            0,
            &[]
        ),
        SeenBitmapError::NonCanonicalOids
    )]
    fn roaring_bitmap_deserialize_rejects_invalid_inputs(
        #[case] bytes: Vec<u8>,
        #[case] expected: SeenBitmapError,
    ) {
        let err = RoaringSeenBitmap::deserialize(&bytes).expect_err("invalid bitmap must fail");
        assert_eq!(err, expected);
    }

    #[test]
    fn roaring_bitmap_deserialize_rejects_phantom_bits() {
        // A payload whose roaring bitmap has bit 5 set, but the OID index
        // only has 1 entry. Position 5 has no corresponding OID.
        let mut phantom = RoaringBitmap::new();
        phantom.insert(0); // valid: maps to the single OID
        phantom.insert(5); // phantom: no OID at index 5

        let mut bitmap_payload = Vec::new();
        phantom
            .serialize_into(&mut bitmap_payload)
            .expect("serialize roaring");

        let bytes = bitmap_bytes(
            BITMAP_MAGIC,
            OidBytes::SHA1_LEN,
            1,
            sha1(0x10).as_slice(),
            bitmap_payload.len() as u32,
            &bitmap_payload,
        );

        // Deserialization must reject payloads where the bitmap references
        // positions beyond the OID index.
        let result = RoaringSeenBitmap::deserialize(&bytes);
        assert!(
            result.is_err(),
            "expected phantom-bit rejection, got bitmap with len={}",
            result.as_ref().unwrap().len()
        );
    }

    #[test]
    fn roaring_bitmap_deserialize_rejects_invalid_bitmap_payload() {
        let bytes = bitmap_bytes(
            BITMAP_MAGIC,
            OidBytes::SHA1_LEN,
            1,
            sha1(0x10).as_slice(),
            0,
            &[],
        );

        let err = RoaringSeenBitmap::deserialize(&bytes).expect_err("empty roaring payload");
        assert!(matches!(err, SeenBitmapError::InvalidBitmap(_)));
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;
    use std::collections::HashSet;

    use proptest::prelude::*;

    const PROPTEST_CASES: u32 = 128;

    fn arb_sha1_oids() -> impl Strategy<Value = Vec<OidBytes>> {
        prop::collection::vec(any::<[u8; 20]>(), 0..128)
            .prop_map(|items| items.into_iter().map(OidBytes::sha1).collect())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn bitmap_round_trip_preserves_state(oids in arb_sha1_oids()) {
            let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            bitmap.insert_batch(&oids).expect("insert");

            let bytes = bitmap.serialize().expect("serialize");
            let decoded = RoaringSeenBitmap::deserialize(&bytes).expect("decode");

            prop_assert_eq!(decoded, bitmap);
        }

        #[test]
        fn bitmap_matches_hashset_oracle(seen in arb_sha1_oids(), probe in arb_sha1_oids()) {
            let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            bitmap.insert_batch(&seen).expect("insert");
            let oracle: HashSet<OidBytes> = seen.iter().copied().collect();

            let flags = bitmap.batch_contains(&probe);
            let expected: Vec<bool> = probe.iter().map(|oid| oracle.contains(oid)).collect();
            prop_assert_eq!(flags, expected);
        }

        #[test]
        fn bitmap_merge_is_associative(a in arb_sha1_oids(), b in arb_sha1_oids(), c in arb_sha1_oids()) {
            let mut ab_c = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            ab_c.insert_batch(&a).expect("a");
            let mut other_b = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            other_b.insert_batch(&b).expect("b");
            let mut other_c = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            other_c.insert_batch(&c).expect("c");
            ab_c.merge(&other_b).expect("merge b");
            ab_c.merge(&other_c).expect("merge c");

            let mut a_bc = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            a_bc.insert_batch(&a).expect("a");
            let mut bc = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            bc.insert_batch(&b).expect("b");
            bc.insert_batch(&c).expect("c");
            a_bc.merge(&bc).expect("merge bc");

            prop_assert_eq!(ab_c, a_bc);
        }

        #[test]
        fn batch_contains_matches_point_queries(seen in arb_sha1_oids(), probe in arb_sha1_oids()) {
            let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            bitmap.insert_batch(&seen).expect("insert");

            let batch = bitmap.batch_contains(&probe);
            let pointwise: Vec<bool> = probe.iter().map(|oid| bitmap.contains(oid)).collect();
            prop_assert_eq!(batch, pointwise);
        }

        #[test]
        fn batch_contains_sorted_matches_unsorted(seen in arb_sha1_oids(), probe in arb_sha1_oids()) {
            let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            bitmap.insert_batch(&seen).expect("insert");

            let mut sorted_probe = probe.clone();
            sorted_probe.sort_unstable();
            // Keep duplicates: batch_contains_sorted accepts non-decreasing
            // input and the two-pointer scan must handle equal neighbors.

            let sorted_result = bitmap.batch_contains_sorted(&sorted_probe);
            let unsorted_result = bitmap.batch_contains(&sorted_probe);
            prop_assert_eq!(sorted_result, unsorted_result);
        }

        #[test]
        fn bitmap_merge_is_commutative(a in arb_sha1_oids(), b in arb_sha1_oids(), probe in arb_sha1_oids()) {
            let mut ab = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            ab.insert_batch(&a).expect("a");
            let mut b_side = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            b_side.insert_batch(&b).expect("b");
            ab.merge(&b_side).expect("merge b into a");

            let mut ba = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            ba.insert_batch(&b).expect("b");
            let mut a_side = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
            a_side.insert_batch(&a).expect("a");
            ba.merge(&a_side).expect("merge a into b");

            let ab_flags = ab.batch_contains(&probe);
            let ba_flags = ba.batch_contains(&probe);
            prop_assert_eq!(ab_flags, ba_flags);
        }
    }
}
