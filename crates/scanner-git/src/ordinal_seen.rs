//! Dense seen-bitset indexed by MIDX ordinal positions.
//!
//! `MidxOrdinalBitset` replaces the flat OID table used by
//! [`RoaringSeenBitmap`](crate::roaring_seen::RoaringSeenBitmap) when callers
//! can resolve probe OIDs through a stable MIDX snapshot. Each bit position
//! corresponds to one entry in the MIDX OIDL chunk, eliminating the 20-byte
//! per-OID index copy on the hot path.

use std::mem::size_of;

use bytemuck::{cast_slice, try_cast_slice};
use gossip_stdx::bitset::DynamicBitSet;
use gossip_stdx::words_for_bits;

use super::midx::{MidxCursor, MidxView};
use super::midx_error::MidxError;
use super::object_id::OidBytes;

const MOBS_MAGIC: [u8; 4] = *b"MOBS";
const MOBS_VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 4 + 32 + 4;
const OBJECT_COUNT_MISMATCH: &str = "ordinal bitset object count mismatch";
/// Hard ceiling on the MOBS payload size accepted during deserialization.
/// 256 MiB supports over 2 billion objects — well beyond any real MIDX — while
/// preventing unbounded memory allocation from corrupt or malicious payloads.
const MAX_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;

/// Errors returned while decoding serialized ordinal seen bitsets.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OrdinalSeenError {
    /// The serialized payload ended before the fixed header was present.
    #[error("truncated ordinal seen payload")]
    Truncated,
    /// The serialized payload had an unexpected magic header.
    #[error("invalid ordinal seen magic header")]
    InvalidMagic,
    /// The serialized payload used an unsupported format version.
    #[error("unsupported ordinal seen version: {0}")]
    UnsupportedVersion(u8),
    /// The serialized payload length did not match the encoded object count.
    #[error("ordinal seen payload length mismatch")]
    LengthMismatch,
    /// The stored cardinality did not match the decoded word contents.
    #[error("ordinal seen payload cardinality mismatch: expected {expected}, actual {actual}")]
    CardinalityMismatch {
        /// Cardinality stored in the fixed header.
        expected: u32,
        /// Cardinality derived from the decoded words.
        actual: u32,
    },
    /// One or more padding bits past the object-count boundary were set.
    #[error("ordinal seen payload sets bits outside the object count")]
    OutOfRangeBits,
    /// The decoded payload exceeds the maximum accepted size.
    #[error("ordinal seen payload too large: {size} bytes (max {max})")]
    PayloadTooLarge {
        /// Actual payload size in bytes.
        size: usize,
        /// Maximum allowed payload size in bytes.
        max: usize,
    },
}

/// Dense bitset indexed by MIDX ordinal positions.
///
/// Each bit position corresponds to an OID index in the MIDX OIDL chunk.
/// Bit `i` is set iff the OID at `midx.oid_at(i)` has been seen.
///
/// Delegates bit storage and manipulation to [`DynamicBitSet`] while adding
/// MIDX-specific metadata (object count, fingerprint) and incremental
/// cardinality tracking.
///
/// # Invariants
/// - `midx_object_count` equals the MIDX object count at construction time.
/// - `midx_fingerprint` identifies which MIDX version the ordinals belong to.
/// - `bits.bit_length() == midx_object_count as usize`.
/// - All set bits are in range `[0, midx_object_count)`.
/// - `cardinality` equals the number of set bits in `bits`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MidxOrdinalBitset {
    bits: DynamicBitSet,
    midx_object_count: u32,
    midx_fingerprint: [u8; 32],
    cardinality: u32,
}

impl MidxOrdinalBitset {
    /// Creates an empty ordinal bitset for one MIDX snapshot.
    #[must_use]
    pub fn new(midx_object_count: u32, midx_fingerprint: [u8; 32]) -> Self {
        Self {
            bits: DynamicBitSet::empty(midx_object_count as usize),
            midx_object_count,
            midx_fingerprint,
            cardinality: 0,
        }
    }

    /// Returns the number of addressable MIDX ordinals.
    #[must_use]
    pub const fn object_count(&self) -> u32 {
        self.midx_object_count
    }

    /// Sets the bit for `ordinal`.
    #[inline]
    pub fn set(&mut self, ordinal: u32) {
        let _ = self.test_and_set(ordinal);
    }

    /// Returns whether the bit for `ordinal` is set.
    #[inline]
    #[must_use]
    pub fn test(&self, ordinal: u32) -> bool {
        assert!(
            ordinal < self.midx_object_count,
            "ordinal bitset access out of range: {ordinal} >= {}",
            self.midx_object_count
        );
        self.bits.is_set(ordinal as usize)
    }

    /// Returns the number of set bits.
    #[must_use]
    pub const fn cardinality(&self) -> u32 {
        self.cardinality
    }

    /// Returns the heap memory used by the backing word storage.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        std::mem::size_of_val(self.bits.as_words())
    }

    /// Returns the fingerprint for the MIDX snapshot this bitset targets.
    #[must_use]
    pub const fn midx_fingerprint(&self) -> &[u8; 32] {
        &self.midx_fingerprint
    }

    /// Returns the serialized size of the MOBS payload.
    #[must_use]
    pub fn serialized_size(&self) -> usize {
        HEADER_LEN + std::mem::size_of_val(self.bits.as_words())
    }

    /// Serializes the bitset into `out`, clearing it first.
    pub fn serialize_into(&self, out: &mut Vec<u8>) {
        out.clear();
        out.reserve(self.serialized_size());
        out.extend_from_slice(&MOBS_MAGIC);
        out.push(MOBS_VERSION);
        out.extend_from_slice(&self.midx_object_count.to_be_bytes());
        out.extend_from_slice(&self.midx_fingerprint);
        out.extend_from_slice(&self.cardinality.to_be_bytes());
        let words = self.bits.as_words();
        if cfg!(target_endian = "little") {
            out.extend_from_slice(cast_slice(words));
        } else {
            for word in words {
                out.extend_from_slice(&word.to_le_bytes());
            }
        }
    }

    /// Serializes the bitset into a deterministic MOBS payload.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize_into(&mut out);
        out
    }

    /// Deserializes a MOBS payload.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, OrdinalSeenError> {
        if bytes.len() < HEADER_LEN {
            return Err(OrdinalSeenError::Truncated);
        }
        if bytes[..4] != MOBS_MAGIC {
            return Err(OrdinalSeenError::InvalidMagic);
        }
        if bytes[4] != MOBS_VERSION {
            return Err(OrdinalSeenError::UnsupportedVersion(bytes[4]));
        }

        let midx_object_count = u32::from_be_bytes(bytes[5..9].try_into().unwrap());
        let mut midx_fingerprint = [0u8; 32];
        midx_fingerprint.copy_from_slice(&bytes[9..41]);
        let cardinality = u32::from_be_bytes(bytes[41..45].try_into().unwrap());

        let word_count = words_for_bits(midx_object_count as usize);
        let payload_len = word_count
            .checked_mul(size_of::<u64>())
            .ok_or(OrdinalSeenError::LengthMismatch)?;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(OrdinalSeenError::PayloadTooLarge {
                size: payload_len,
                max: MAX_PAYLOAD_BYTES,
            });
        }
        let expected_len = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(OrdinalSeenError::LengthMismatch)?;
        if bytes.len() != expected_len {
            return Err(OrdinalSeenError::LengthMismatch);
        }

        let payload = &bytes[HEADER_LEN..];
        let words: Vec<u64> = if cfg!(target_endian = "little") {
            match try_cast_slice::<u8, u64>(payload) {
                Ok(raw_words) => raw_words.to_vec(),
                Err(_) => decode_words_le(payload),
            }
        } else {
            decode_words_le(payload)
        };

        // Verify padding bits are zero before constructing the DynamicBitSet,
        // which requires this invariant.
        if let Some(&last_word) = words.last() {
            let remainder = midx_object_count % 64;
            // When remainder == 0 and words is non-empty, all 64 bits are valid
            // so there are no padding bits to check.
            let padding_mask = if remainder == 0 {
                0
            } else {
                !((1u64 << remainder) - 1)
            };
            if last_word & padding_mask != 0 {
                return Err(OrdinalSeenError::OutOfRangeBits);
            }
        }

        let actual_cardinality = count_set_bits(&words, midx_object_count);
        if actual_cardinality != cardinality {
            return Err(OrdinalSeenError::CardinalityMismatch {
                expected: cardinality,
                actual: actual_cardinality,
            });
        }

        let bits = DynamicBitSet::from_words(words, midx_object_count as usize);
        Ok(Self {
            bits,
            midx_object_count,
            midx_fingerprint,
            cardinality,
        })
    }

    /// Batch membership query using MIDX ordinal resolution.
    ///
    /// Sorted inputs use `MidxView::find_oid_sorted` with a streaming cursor.
    /// Duplicate OIDs reuse the previous lookup result so the method preserves
    /// the non-decreasing input contract already used by `RoaringSeenBitmap`.
    ///
    /// # Errors
    ///
    /// Returns [`MidxError`] if the MIDX object count does not match the
    /// bitset, or if an OID lookup encounters a corrupt MIDX.
    pub fn batch_contains_sorted(
        &self,
        midx: &MidxView<'_>,
        oids: &[OidBytes],
    ) -> Result<Vec<bool>, MidxError> {
        let mut result = Vec::with_capacity(oids.len());
        self.batch_contains_sorted_into(midx, oids, &mut result)?;
        Ok(result)
    }

    /// Like [`batch_contains_sorted`](Self::batch_contains_sorted) but writes
    /// results into a caller-provided buffer, avoiding a per-call allocation
    /// when the caller can reuse the same `Vec` across batches.
    ///
    /// `out` is cleared before results are written.
    ///
    /// # Errors
    ///
    /// Returns [`MidxError`] if the MIDX object count does not match the
    /// bitset, or if an OID lookup encounters a corrupt MIDX.
    pub fn batch_contains_sorted_into(
        &self,
        midx: &MidxView<'_>,
        oids: &[OidBytes],
        out: &mut Vec<bool>,
    ) -> Result<(), MidxError> {
        self.validate_view(midx)?;

        out.clear();
        out.reserve(oids.len());
        let mut cursor = MidxCursor::default();
        let mut previous_oid: Option<&OidBytes> = None;
        let mut previous_seen = false;
        for oid in oids {
            if let Some(prev) = previous_oid {
                if prev > oid {
                    return Err(MidxError::InputNotSorted);
                }
                if prev == oid {
                    out.push(previous_seen);
                    continue;
                }
            }
            let seen = match midx.find_oid_sorted(&mut cursor, oid) {
                Ok(Some(ordinal)) => self.test(ordinal),
                Ok(None) => false,
                Err(e) => return Err(e),
            };
            out.push(seen);
            previous_oid = Some(oid);
            previous_seen = seen;
        }
        Ok(())
    }

    /// Records a batch of OIDs as seen by resolving their MIDX ordinals.
    ///
    /// Returns the count of newly marked ordinals. Inputs must be sorted in
    /// non-decreasing order. Duplicate OIDs are allowed and counted once.
    ///
    /// Sort order is validated upfront so a rejection never leaves the bitset
    /// in a partially-modified state. OID length mismatches (e.g. SHA-256
    /// probes against a SHA-1 MIDX) are treated as "not found," matching the
    /// read-path behavior in [`batch_contains_sorted_into`](Self::batch_contains_sorted_into).
    pub fn mark_seen_batch(
        &mut self,
        midx: &MidxView<'_>,
        oids: &[OidBytes],
    ) -> Result<u32, MidxError> {
        self.validate_view(midx)?;

        if oids.windows(2).any(|pair| pair[0] > pair[1]) {
            return Err(MidxError::InputNotSorted);
        }

        let mut newly_marked = 0u32;
        let mut cursor = MidxCursor::default();
        let mut previous_oid: Option<&OidBytes> = None;

        for oid in oids {
            if previous_oid == Some(oid) {
                continue;
            }

            let ordinal = match midx.find_oid_sorted(&mut cursor, oid) {
                Ok(found) => found,
                // OID length mismatch (e.g. SHA-256 probe against SHA-1 MIDX)
                // is treated as "not found" rather than a corruption error,
                // matching the read-path behavior.
                Err(MidxError::InputOidLengthMismatch { .. }) => None,
                Err(e) => return Err(e),
            };
            if let Some(ordinal) = ordinal {
                newly_marked += u32::from(self.test_and_set(ordinal));
            }
            previous_oid = Some(oid);
        }

        Ok(newly_marked)
    }

    /// Checks that the MIDX view is compatible with this bitset.
    ///
    /// Currently validates object count only. Fingerprint validation requires
    /// `MidxView` to expose a checksum accessor, which is not yet available.
    /// Until then, callers must ensure the `MidxView` matches the snapshot
    /// used to construct this bitset (i.e. the same MIDX file on disk).
    #[inline]
    fn validate_view(&self, midx: &MidxView<'_>) -> Result<(), MidxError> {
        if midx.object_count() != self.midx_object_count {
            return Err(MidxError::corrupt(OBJECT_COUNT_MISMATCH));
        }
        // Fingerprint validation requires MidxView to expose the trailing MIDX
        // checksum (currently not parsed). Until then, callers must ensure the
        // bitset and view refer to the same MIDX snapshot.
        Ok(())
    }

    #[inline]
    fn test_and_set(&mut self, ordinal: u32) -> bool {
        assert!(
            ordinal < self.midx_object_count,
            "ordinal bitset access out of range: {ordinal} >= {}",
            self.midx_object_count
        );
        let idx = ordinal as usize;
        if !self.bits.is_set(idx) {
            self.bits.set(idx);
            self.cardinality += 1;
            true
        } else {
            false
        }
    }
}

#[inline]
fn decode_words_le(payload: &[u8]) -> Vec<u64> {
    payload
        .chunks_exact(size_of::<u64>())
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

/// Counts set bits in raw words, masking the last word to `bit_count` bits.
/// Used during deserialization to validate the stored cardinality before
/// constructing a `DynamicBitSet`.
fn count_set_bits(words: &[u64], bit_count: u32) -> u32 {
    if words.is_empty() {
        return 0;
    }
    let last = words.len() - 1;
    let mut total = 0u32;
    for &word in &words[..last] {
        total += word.count_ones();
    }
    let remainder = bit_count % 64;
    // When remainder == 0 and words is non-empty, all 64 bits are valid.
    let mask = if remainder == 0 {
        u64::MAX
    } else {
        (1u64 << remainder) - 1
    };
    total + (words[last] & mask).count_ones()
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;
    use crate::midx_test_builder::MidxBuilder;
    use crate::{MidxView, ObjectFormat};

    const PROPTEST_CASES: u32 = 64;

    fn oid_raw_from_u32(value: u32) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes[..4].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    fn oid_from_u32(value: u32) -> OidBytes {
        OidBytes::sha1(oid_raw_from_u32(value))
    }

    fn build_test_midx(object_count: u32) -> Vec<u8> {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-0.pack");
        for value in 0..object_count {
            builder.add_object(oid_raw_from_u32(value), 0, value as u64);
        }
        builder.build()
    }

    #[test]
    fn heap_bytes_matches_dense_1m_layout() {
        let bitset = MidxOrdinalBitset::new(1_000_000, [0x5A; 32]);
        assert_eq!(bitset.heap_bytes(), 125_000);
        assert_eq!(bitset.serialized_size(), HEADER_LEN + 125_000);
    }

    #[test]
    fn set_and_test_round_trip_all_boundaries() {
        let mut bitset = MidxOrdinalBitset::new(130, [0xAB; 32]);
        for ordinal in [0, 1, 63, 64, 65, 129] {
            assert!(!bitset.test(ordinal));
            bitset.set(ordinal);
            assert!(bitset.test(ordinal));
        }
        assert_eq!(bitset.cardinality(), 6);
    }

    #[test]
    fn batch_contains_sorted_preserves_duplicates_and_midx_misses() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let mut bitset = MidxOrdinalBitset::new(midx.object_count(), [0x11; 32]);
        bitset.set(1);
        bitset.set(4);

        let probes = vec![
            oid_from_u32(1),
            oid_from_u32(1),
            oid_from_u32(3),
            oid_from_u32(4),
            oid_from_u32(9),
        ];
        let flags = bitset
            .batch_contains_sorted(&midx, &probes)
            .expect("batch lookup");
        assert_eq!(flags, vec![true, true, false, true, false]);
    }

    #[test]
    fn mark_seen_batch_counts_new_ordinals_once() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let mut bitset = MidxOrdinalBitset::new(midx.object_count(), [0x22; 32]);

        let newly_marked = bitset
            .mark_seen_batch(
                &midx,
                &[
                    oid_from_u32(1),
                    oid_from_u32(1),
                    oid_from_u32(2),
                    oid_from_u32(9),
                ],
            )
            .expect("mark batch");

        assert_eq!(newly_marked, 2);
        assert!(bitset.test(1));
        assert!(bitset.test(2));
        assert_eq!(bitset.cardinality(), 2);
    }

    #[test]
    fn mark_seen_batch_rejects_decreasing_input() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let mut bitset = MidxOrdinalBitset::new(midx.object_count(), [0x33; 32]);
        let err = bitset
            .mark_seen_batch(&midx, &[oid_from_u32(2), oid_from_u32(1)])
            .expect_err("decreasing input must fail");
        assert!(matches!(err, MidxError::InputNotSorted));
    }

    #[test]
    fn mark_seen_batch_does_not_mutate_on_sort_rejection() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let mut bitset = MidxOrdinalBitset::new(midx.object_count(), [0x33; 32]);
        // First OID would be a hit, second is unsorted relative to first.
        let err = bitset
            .mark_seen_batch(&midx, &[oid_from_u32(5), oid_from_u32(1)])
            .expect_err("unsorted");
        assert!(matches!(err, MidxError::InputNotSorted));
        // No bits should have been set — the sort check fires before mutation.
        assert_eq!(bitset.cardinality(), 0);
        assert!(!bitset.test(5));
    }

    #[test]
    fn mark_seen_batch_swallows_oid_length_mismatch_as_miss() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let mut bitset = MidxOrdinalBitset::new(midx.object_count(), [0x33; 32]);
        // SHA-256 OID against a SHA-1 MIDX: treated as "not found", not an error.
        let newly_marked = bitset
            .mark_seen_batch(&midx, &[oid_from_u32(1), OidBytes::sha256([0x55; 32])])
            .expect("length mismatch should be swallowed");
        assert_eq!(newly_marked, 1);
        assert!(bitset.test(1));
    }

    #[test]
    fn serialize_matches_golden_mobs_bytes() {
        let mut bitset = MidxOrdinalBitset::new(10, [0xA5; 32]);
        bitset.set(0);
        bitset.set(2);
        bitset.set(9);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"MOBS");
        expected.push(1);
        expected.extend_from_slice(&10u32.to_be_bytes());
        expected.extend_from_slice(&[0xA5; 32]);
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(&517u64.to_le_bytes());

        assert_eq!(bitset.serialize(), expected);
    }

    #[test]
    fn deserialize_round_trips_from_misaligned_slice() {
        let mut bitset = MidxOrdinalBitset::new(70, [0x44; 32]);
        bitset.set(1);
        bitset.set(63);
        bitset.set(64);
        let bytes = bitset.serialize();

        let mut misaligned = Vec::with_capacity(bytes.len() + 1);
        misaligned.push(0xFF);
        misaligned.extend_from_slice(&bytes);

        let decoded = MidxOrdinalBitset::deserialize(&misaligned[1..]).expect("decode");
        assert_eq!(decoded, bitset);
    }

    #[test]
    fn deserialize_rejects_padding_bits() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"MOBS");
        bytes.push(1);
        bytes.extend_from_slice(&65u32.to_be_bytes());
        bytes.extend_from_slice(&[0x77; 32]);
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&(1u64 << 63).to_le_bytes());

        let err = MidxOrdinalBitset::deserialize(&bytes).expect_err("padding bits must fail");
        assert_eq!(err, OrdinalSeenError::OutOfRangeBits);
    }

    #[test]
    fn deserialize_rejects_oversized_payload() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"MOBS");
        bytes.push(1);
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.extend_from_slice(&[0x00; 32]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        let err = MidxOrdinalBitset::deserialize(&bytes).expect_err("oversized");
        assert!(matches!(err, OrdinalSeenError::PayloadTooLarge { .. }));
    }

    #[test]
    fn deserialize_rejects_truncated_header() {
        let err = MidxOrdinalBitset::deserialize(&[0u8; HEADER_LEN - 1]).expect_err("truncated");
        assert_eq!(err, OrdinalSeenError::Truncated);
    }

    #[test]
    fn deserialize_rejects_invalid_magic() {
        let mut bytes = vec![0u8; HEADER_LEN + 8];
        bytes[..4].copy_from_slice(b"XXXX");
        bytes[4] = MOBS_VERSION;
        bytes[5..9].copy_from_slice(&1u32.to_be_bytes());
        let err = MidxOrdinalBitset::deserialize(&bytes).expect_err("bad magic");
        assert_eq!(err, OrdinalSeenError::InvalidMagic);
    }

    #[test]
    fn deserialize_rejects_unsupported_version() {
        let mut bytes = vec![0u8; HEADER_LEN + 8];
        bytes[..4].copy_from_slice(b"MOBS");
        bytes[4] = 99;
        bytes[5..9].copy_from_slice(&1u32.to_be_bytes());
        let err = MidxOrdinalBitset::deserialize(&bytes).expect_err("bad version");
        assert_eq!(err, OrdinalSeenError::UnsupportedVersion(99));
    }

    #[test]
    fn deserialize_rejects_length_mismatch() {
        let bitset = MidxOrdinalBitset::new(10, [0x00; 32]);
        let mut bytes = bitset.serialize();
        bytes.push(0xFF);
        let err = MidxOrdinalBitset::deserialize(&bytes).expect_err("length mismatch");
        assert_eq!(err, OrdinalSeenError::LengthMismatch);
    }

    #[test]
    fn deserialize_rejects_cardinality_mismatch() {
        let mut bitset = MidxOrdinalBitset::new(10, [0x00; 32]);
        bitset.set(0);
        let mut bytes = bitset.serialize();
        // Corrupt cardinality from 1 to 2.
        bytes[41..45].copy_from_slice(&2u32.to_be_bytes());
        let err = MidxOrdinalBitset::deserialize(&bytes).expect_err("cardinality");
        assert_eq!(
            err,
            OrdinalSeenError::CardinalityMismatch {
                expected: 2,
                actual: 1
            }
        );
    }

    #[test]
    fn batch_contains_sorted_rejects_unsorted_input() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let bitset = MidxOrdinalBitset::new(midx.object_count(), [0x55; 32]);
        let unsorted = vec![oid_from_u32(3), oid_from_u32(1)];
        let err = bitset
            .batch_contains_sorted(&midx, &unsorted)
            .expect_err("unsorted");
        assert!(matches!(err, MidxError::InputNotSorted));
    }

    #[test]
    fn batch_contains_sorted_rejects_mismatched_midx() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let bitset = MidxOrdinalBitset::new(16, [0x66; 32]);
        let err = bitset
            .batch_contains_sorted(&midx, &[oid_from_u32(1)])
            .expect_err("mismatched");
        assert!(matches!(err, MidxError::MidxCorrupt { .. }));
    }

    #[test]
    fn mark_seen_batch_rejects_mismatched_midx() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let mut bitset = MidxOrdinalBitset::new(16, [0x77; 32]);
        let err = bitset
            .mark_seen_batch(&midx, &[oid_from_u32(1)])
            .expect_err("mismatched");
        assert!(matches!(err, MidxError::MidxCorrupt { .. }));
    }

    #[test]
    fn batch_contains_sorted_rejects_oid_length_mismatch() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let bitset = MidxOrdinalBitset::new(midx.object_count(), [0xAA; 32]);
        let probes = vec![OidBytes::sha256([0x55; 32])];
        let err = bitset
            .batch_contains_sorted(&midx, &probes)
            .expect_err("length mismatch");
        assert!(matches!(err, MidxError::InputOidLengthMismatch { .. }));
    }

    #[test]
    fn serialize_deserialize_zero_objects() {
        let bitset = MidxOrdinalBitset::new(0, [0xCC; 32]);
        assert_eq!(bitset.cardinality(), 0);
        assert_eq!(bitset.object_count(), 0);
        assert_eq!(bitset.heap_bytes(), 0);

        let bytes = bitset.serialize();
        assert_eq!(bytes.len(), HEADER_LEN);

        let decoded = MidxOrdinalBitset::deserialize(&bytes).expect("zero-object round-trip");
        assert_eq!(decoded, bitset);
    }

    #[test]
    fn mark_seen_batch_with_empty_input() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let mut bitset = MidxOrdinalBitset::new(midx.object_count(), [0x88; 32]);
        let newly_marked = bitset.mark_seen_batch(&midx, &[]).expect("empty batch");
        assert_eq!(newly_marked, 0);
        assert_eq!(bitset.cardinality(), 0);
    }

    #[test]
    fn serialize_into_clears_preexisting_buffer() {
        let mut bitset = MidxOrdinalBitset::new(10, [0xDD; 32]);
        bitset.set(3);
        bitset.set(7);

        let expected = bitset.serialize();
        let mut buf = vec![0xFF; 1024];
        bitset.serialize_into(&mut buf);
        assert_eq!(buf, expected);
    }

    #[test]
    fn batch_contains_sorted_into_reuses_buffer() {
        let midx_bytes = build_test_midx(8);
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
        let mut bitset = MidxOrdinalBitset::new(midx.object_count(), [0xEE; 32]);
        bitset.set(0);
        bitset.set(3);

        let mut out = Vec::new();

        // First call.
        let probes_a = vec![oid_from_u32(0), oid_from_u32(1)];
        bitset
            .batch_contains_sorted_into(&midx, &probes_a, &mut out)
            .expect("first batch");
        assert_eq!(out, vec![true, false]);

        // Second call reuses the same buffer with different inputs.
        let probes_b = vec![oid_from_u32(3), oid_from_u32(5)];
        bitset
            .batch_contains_sorted_into(&midx, &probes_b, &mut out)
            .expect("second batch");
        assert_eq!(out, vec![true, false]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn serialization_round_trip_preserves_state(
            object_count in 0u16..256,
            fingerprint in any::<[u8; 32]>(),
            ordinals in vec(0u16..256, 0..256),
        ) {
            let object_count = object_count as u32;
            let mut bitset = MidxOrdinalBitset::new(object_count, fingerprint);
            for ordinal in ordinals {
                if (ordinal as u32) < object_count {
                    bitset.set(ordinal as u32);
                }
            }

            let bytes = bitset.serialize();
            let decoded = MidxOrdinalBitset::deserialize(&bytes).expect("decode");

            prop_assert_eq!(decoded.serialized_size(), bytes.len());
            prop_assert_eq!(decoded, bitset);
        }

        #[test]
        fn batch_contains_sorted_matches_oracle(
            seen in vec(0u16..256, 0..256),
            probe in vec(0u16..320, 0..256),
        ) {
            let midx_bytes = build_test_midx(256);
            let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
            let mut bitset = MidxOrdinalBitset::new(midx.object_count(), [0x99; 32]);
            let mut oracle = vec![false; 256];
            for ordinal in seen {
                let ordinal = ordinal as usize;
                oracle[ordinal] = true;
                bitset.set(ordinal as u32);
            }

            let mut probe = probe;
            probe.sort_unstable();
            let expected: Vec<bool> = probe
                .iter()
                .map(|&value| {
                    let value = value as usize;
                    value < oracle.len() && oracle[value]
                })
                .collect();
            let probes: Vec<OidBytes> = probe
                .iter()
                .map(|&value| oid_from_u32(value as u32))
                .collect();

            prop_assert_eq!(bitset.batch_contains_sorted(&midx, &probes).expect("batch lookup"), expected);
        }

        #[test]
        fn mark_seen_batch_matches_oracle(
            pre_seen in vec(0u16..256, 0..128),
            batch in vec(0u16..320, 0..128),
        ) {
            let midx_bytes = build_test_midx(256);
            let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).expect("midx");
            let mut bitset = MidxOrdinalBitset::new(midx.object_count(), [0xBB; 32]);

            let mut already_set = std::collections::HashSet::new();
            for &ordinal in &pre_seen {
                if (ordinal as u32) < 256 {
                    bitset.set(ordinal as u32);
                    already_set.insert(ordinal);
                }
            }
            let card_before = bitset.cardinality();

            let mut batch = batch;
            batch.sort_unstable();
            let oids: Vec<OidBytes> = batch.iter().map(|&v| oid_from_u32(v as u32)).collect();

            let newly_marked = bitset.mark_seen_batch(&midx, &oids).expect("mark");

            // Oracle: count unique OIDs that are in MIDX range AND not already set.
            let mut expected_new = 0u32;
            let mut counted = std::collections::HashSet::new();
            for &v in &batch {
                if (v as u32) < 256 && !already_set.contains(&v) && counted.insert(v) {
                    expected_new += 1;
                }
            }

            prop_assert_eq!(newly_marked, expected_new);
            prop_assert_eq!(bitset.cardinality(), card_before + expected_new);
        }
    }
}
