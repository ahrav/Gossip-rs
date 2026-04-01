//! Seen-bitmap delta and RocksDB bitmap encoding helpers.
//!
//! `SeenBitmapDelta` is the finalize-time payload: it carries the sorted OIDs
//! that were scanned during the current finalize call. The persisted on-disk
//! format is `RoaringSeenBitmap`, which stores the scope's sorted OID index and
//! a Roaring bitmap over that index.

use super::object_id::OidBytes;

#[cfg(feature = "rocksdb")]
use super::errors::SpillError;
#[cfg(feature = "rocksdb")]
use super::seen_store::SeenBlobStore;
#[cfg(feature = "rocksdb")]
use roaring::RoaringBitmap;

const DELTA_MAGIC: [u8; 4] = *b"RSBD";
#[cfg(feature = "rocksdb")]
const BITMAP_MAGIC: [u8; 4] = *b"RSBM";

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
    #[cfg(feature = "rocksdb")]
    #[error("invalid roaring bitmap payload: {0}")]
    InvalidBitmap(String),
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
    pub fn from_oids(oids: &[OidBytes]) -> Result<Self, SeenBitmapError> {
        let (oid_len, oids) = canonicalize_oids(oids)?;
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
        out.extend_from_slice(&(self.oids.len() as u32).to_be_bytes());
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
        let expected_len = 9 + payload_len;
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

#[cfg(feature = "rocksdb")]
fn insert_position(bitmap: &mut RoaringBitmap, pos: usize) -> Result<(), SeenBitmapError> {
    bitmap.insert(u32::try_from(pos).map_err(|_| SeenBitmapError::TooManyOids(pos + 1))?);
    Ok(())
}

#[cfg(feature = "rocksdb")]
fn bitmap_contains(bitmap: &RoaringBitmap, pos: usize) -> bool {
    bitmap.contains(u32::try_from(pos).expect("bitmap position exceeds u32::MAX"))
}

/// Persisted seen bitmap for one `(repo_id, policy_hash)` scope.
#[cfg(feature = "rocksdb")]
#[derive(Clone, Debug, PartialEq)]
pub struct RoaringSeenBitmap {
    oid_len: u8,
    oids: Vec<OidBytes>,
    seen: RoaringBitmap,
}

#[cfg(feature = "rocksdb")]
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

    /// Returns the number of seen OIDs tracked by this bitmap.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::try_from(self.seen.len()).unwrap_or(usize::MAX)
    }

    /// Returns true when the bitmap tracks no seen OIDs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
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
    #[must_use]
    pub fn batch_contains(&self, oids: &[OidBytes]) -> Vec<bool> {
        oids.iter().map(|oid| self.contains(oid)).collect()
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

    fn merge_delta(&mut self, delta: &SeenBitmapDelta) -> Result<(), SeenBitmapError> {
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
        let _ = u32_len(self.oids.len().saturating_add(other_oids.len()))?;

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

        self.oids = merged_oids;
        self.seen = merged_seen;
        Ok(())
    }

    /// Serializes the persisted bitmap payload.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let bitmap_len = self.seen.serialized_size();
        let mut out = Vec::with_capacity(self.serialized_size());
        out.extend_from_slice(&BITMAP_MAGIC);
        out.push(self.oid_len);
        out.extend_from_slice(&(self.oids.len() as u32).to_be_bytes());
        for oid in &self.oids {
            debug_assert_eq!(oid.len(), self.oid_len, "bitmap OID length mismatch");
            out.extend_from_slice(oid.as_slice());
        }
        out.extend_from_slice(&(bitmap_len as u32).to_be_bytes());
        self.seen
            .serialize_into(&mut out)
            .expect("Vec-backed bitmap serialization must be infallible");
        out
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
        let oid_count = u32::from_be_bytes(bytes[5..9].try_into().unwrap()) as usize;
        let oid_bytes_len = oid_count
            .checked_mul(oid_len as usize)
            .ok_or(SeenBitmapError::LengthMismatch)?;
        let bitmap_len_offset = 9 + oid_bytes_len;
        if bytes.len() < bitmap_len_offset + 4 {
            return Err(SeenBitmapError::Truncated);
        }
        let bitmap_len = u32::from_be_bytes(
            bytes[bitmap_len_offset..bitmap_len_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let expected_len = bitmap_len_offset + 4 + bitmap_len;
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

        Ok(Self {
            oid_len,
            oids,
            seen: bitmap,
        })
    }
}

/// In-memory seen store backed by a roaring bitmap scope snapshot.
#[cfg(feature = "rocksdb")]
#[derive(Clone, Debug, PartialEq)]
pub struct RoaringSeenStore {
    bitmap: RoaringSeenBitmap,
}

#[cfg(feature = "rocksdb")]
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

    /// Clones the underlying bitmap snapshot.
    #[must_use]
    pub fn clone_bitmap(&self) -> RoaringSeenBitmap {
        self.bitmap.clone()
    }

    /// Replaces the stored bitmap snapshot.
    pub fn replace_bitmap(&mut self, bitmap: RoaringSeenBitmap) {
        self.bitmap = bitmap;
    }
}

#[cfg(feature = "rocksdb")]
impl SeenBlobStore for RoaringSeenStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        Ok(self.bitmap.batch_contains(oids))
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

    #[cfg(feature = "rocksdb")]
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

    #[cfg(feature = "rocksdb")]
    #[test]
    fn roaring_bitmap_round_trips() {
        let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        bitmap
            .insert_batch(&[sha1(0x10), sha1(0x20), sha1(0x30)])
            .expect("insert");

        let bytes = bitmap.serialize();
        let decoded = RoaringSeenBitmap::deserialize(&bytes).expect("decode");
        assert_eq!(decoded, bitmap);
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn roaring_bitmap_serialization_golden_value() {
        let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        bitmap
            .insert_batch(&[sha1(0x10), sha1(0x20), sha1(0x30)])
            .expect("insert");

        let actual: String = bitmap
            .serialize()
            .into_iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        // Pin the exact serialization so on-disk format changes stay explicit.
        const EXPECTED: &str =
            "5253424d1400000003101010101010101010101010101010101010101020202020202020202020202020202020202020203030303030303030303030303030303030303030000000163a300000010000000000020010000000000001000200";
        assert_eq!(actual, EXPECTED, "roaring bitmap serialization changed");
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn roaring_bitmap_empty_query_is_all_false() {
        let bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        assert_eq!(
            bitmap.batch_contains(&[sha1(0x11), sha1(0x22)]),
            vec![false, false]
        );
    }

    #[cfg(feature = "rocksdb")]
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

    #[cfg(feature = "rocksdb")]
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

    #[cfg(feature = "rocksdb")]
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

#[cfg(all(test, feature = "rocksdb", feature = "stdx-proptest"))]
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

            let bytes = bitmap.serialize();
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
    }
}
