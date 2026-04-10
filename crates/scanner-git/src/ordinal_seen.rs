//! Dense seen-bitset indexed by MIDX ordinal positions.
//!
//! `MidxOrdinalBitset` replaces the flat OID table used by
//! [`RoaringSeenBitmap`](crate::roaring_seen::RoaringSeenBitmap) when callers
//! can resolve probe OIDs through a stable MIDX snapshot. Each bit position
//! corresponds to one entry in the MIDX OIDL chunk, eliminating the 20-byte
//! per-OID index copy on the hot path.

use std::cell::RefCell;
use std::mem::size_of;

use blake3::Hasher;
use bytemuck::{cast_slice, try_cast_slice};
use gossip_stdx::bitset::DynamicBitSet;
use gossip_stdx::words_for_bits;

use tracing::debug;

use super::bytes::BytesView;
use super::errors::SpillError;
use super::midx::{MidxCursor, MidxView, ValidatedMidxLayout};
use super::midx_error::MidxError;
use super::object_id::{ObjectFormat, OidBytes};
use super::repo_open::RepoArtifactFingerprint;
use super::roaring_seen::{RoaringSeenBitmap, RoaringSeenStore};
use super::seen_store::SeenBlobStore;

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
    /// # Safety Contract
    ///
    /// The caller must ensure that `midx` refers to the same MIDX snapshot used
    /// to construct this bitset. The method validates object-count parity but
    /// cannot verify MIDX identity (the trailing checksum is not yet parsed).
    /// Using a different MIDX with the same object count produces silently wrong
    /// results.
    ///
    /// # Errors
    ///
    /// Returns [`MidxError`] if the MIDX object count does not match the
    /// bitset, if the input OIDs are not in non-decreasing order, or if an
    /// OID lookup encounters a corrupt MIDX.
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
    /// # Safety Contract
    ///
    /// The caller must ensure that `midx` refers to the same MIDX snapshot used
    /// to construct this bitset. The method validates object-count parity but
    /// cannot verify MIDX identity (the trailing checksum is not yet parsed).
    /// Using a different MIDX with the same object count produces silently wrong
    /// results.
    ///
    /// # Errors
    ///
    /// Returns [`MidxError`] if the MIDX object count does not match the
    /// bitset, if the input OIDs are not in non-decreasing order, or if an
    /// OID lookup encounters a corrupt MIDX.
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
    /// probes against a SHA-1 MIDX) are treated as "not found" rather than
    /// an error, unlike [`batch_contains_sorted_into`](Self::batch_contains_sorted_into)
    /// which propagates [`MidxError::InputOidLengthMismatch`].
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

/// Raw MIDX bytes and metadata for one snapshot.
///
/// Replaced via [`HybridSeenStore::set_midx_snapshot`] whenever the pack
/// index changes. Reconstructed into a short-lived [`MidxView`] via cached
/// layout offsets (no re-parsing) on each query batch. Storing the raw bytes
/// (rather than a pre-parsed view) avoids self-referential lifetime issues
/// since `MidxView` borrows from the byte slice.
#[derive(Clone, Debug)]
struct ConfiguredMidxSnapshot {
    bytes: BytesView,
    artifact_fingerprint: RepoArtifactFingerprint,
    /// Pre-validated chunk offsets for zero-parse `MidxView` reconstruction.
    layout: ValidatedMidxLayout,
    /// Pre-folded fingerprint, avoiding a blake3 hash per cache rebuild.
    folded_fingerprint: [u8; 32],
}

impl ConfiguredMidxSnapshot {
    /// Reconstructs a `MidxView` from cached offsets without re-validation.
    #[inline]
    fn view(&self) -> MidxView<'_> {
        MidxView::from_layout(self.bytes.as_slice(), &self.layout)
    }
}

/// Cached ordinal bitset derived from the roaring bitmap for one MIDX
/// snapshot. Invalidated and lazily rebuilt whenever the
/// `artifact_fingerprint` changes.
#[derive(Clone, Debug)]
struct OrdinalCache {
    bitset: MidxOrdinalBitset,
    artifact_fingerprint: RepoArtifactFingerprint,
}

/// Seen-store wrapper that serves MIDX-resident OIDs from an ordinal bitset
/// and falls back to the persisted roaring bitmap for loose objects.
///
/// The roaring bitmap remains the authoritative store. The ordinal cache is a
/// derived acceleration structure tied to one MIDX snapshot and is rebuilt
/// lazily after the configured snapshot changes.
///
/// # Thread Safety
///
/// This type uses [`RefCell`] for interior mutability of the ordinal cache
/// and is therefore `!Sync`. It is designed for single-threaded scan loops.
/// The following methods access the `RefCell`: [`batch_check_seen`](SeenBlobStore::batch_check_seen),
/// [`rebuild_from_fallback`](Self::rebuild_from_fallback),
/// [`is_valid_for_fingerprint`](Self::is_valid_for_fingerprint),
/// [`fallback_mut`](Self::fallback_mut),
/// [`set_midx_snapshot`](Self::set_midx_snapshot), and
/// [`clear_midx_snapshot`](Self::clear_midx_snapshot).
/// None of these may be called concurrently. If multi-threaded access is
/// needed in the future, the `RefCell` should be replaced with an `RwLock`
/// (to allow concurrent reads on the fast path).
#[derive(Clone, Debug)]
pub struct HybridSeenStore {
    fallback: RoaringSeenStore,
    midx_snapshot: RefCell<Option<ConfiguredMidxSnapshot>>,
    ordinal: RefCell<Option<OrdinalCache>>,
}

impl HybridSeenStore {
    /// Builds a hybrid store without a MIDX snapshot.
    #[must_use]
    pub fn new(fallback: RoaringSeenStore) -> Self {
        Self {
            fallback,
            midx_snapshot: RefCell::new(None),
            ordinal: RefCell::new(None),
        }
    }

    /// Builds a hybrid store with an initial MIDX snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SpillError`] when the MIDX bytes do not parse for the given
    /// object format or when the snapshot format disagrees with the roaring
    /// bitmap's object length.
    pub fn with_midx(
        fallback: RoaringSeenStore,
        midx_bytes: BytesView,
        object_format: ObjectFormat,
        artifact_fingerprint: RepoArtifactFingerprint,
    ) -> Result<Self, SpillError> {
        let store = Self::new(fallback);
        store.set_midx_snapshot(midx_bytes, object_format, artifact_fingerprint)?;
        Ok(store)
    }

    /// Returns the authoritative roaring fallback store.
    #[must_use]
    pub fn fallback(&self) -> &RoaringSeenStore {
        &self.fallback
    }

    /// Returns the authoritative roaring fallback store, clearing any cached
    /// ordinal bits before the caller mutates the bitmap.
    pub fn fallback_mut(&mut self) -> &mut RoaringSeenStore {
        self.ordinal.get_mut().take();
        &mut self.fallback
    }

    /// Replaces the current MIDX snapshot and unconditionally invalidates the
    /// ordinal cache.
    ///
    /// # Errors
    ///
    /// Returns [`SpillError`] when the snapshot object format disagrees with
    /// the roaring bitmap's object length or when the MIDX bytes do not parse.
    pub fn set_midx_snapshot(
        &self,
        midx_bytes: BytesView,
        object_format: ObjectFormat,
        artifact_fingerprint: RepoArtifactFingerprint,
    ) -> Result<(), SpillError> {
        validate_snapshot_format(&self.fallback, object_format)?;
        let midx = MidxView::parse(midx_bytes.as_slice(), object_format)?;
        let layout = midx.layout(midx_bytes.as_slice());
        let folded_fingerprint = fold_artifact_fingerprint(&artifact_fingerprint);
        *self.midx_snapshot.borrow_mut() = Some(ConfiguredMidxSnapshot {
            bytes: midx_bytes,
            artifact_fingerprint,
            layout,
            folded_fingerprint,
        });
        // Always invalidate: RepoArtifactFingerprint hashes file metadata
        // (basename, size, mtime), not content. Two different MIDX files can
        // share a fingerprint, so a stale cache must never be reused.
        self.ordinal.borrow_mut().take();
        Ok(())
    }

    /// Discards the configured MIDX snapshot and any cached ordinal bits.
    pub fn clear_midx_snapshot(&self) {
        self.midx_snapshot.borrow_mut().take();
        self.ordinal.borrow_mut().take();
    }

    /// Returns whether the cached ordinal bitset targets `fingerprint`.
    #[must_use]
    pub fn is_valid_for_fingerprint(&self, fingerprint: &RepoArtifactFingerprint) -> bool {
        self.ordinal
            .borrow()
            .as_ref()
            .is_some_and(|cache| &cache.artifact_fingerprint == fingerprint)
    }

    /// Rebuilds the ordinal cache from the authoritative roaring bitmap.
    ///
    /// If no MIDX snapshot is configured, the ordinal cache is cleared and the
    /// method returns `Ok(())`. OIDs missing from the configured MIDX remain
    /// available through the roaring fallback and are not added to the ordinal
    /// bitset.
    ///
    /// # Errors
    ///
    /// Returns [`SpillError`] when the configured MIDX snapshot is invalid.
    #[must_use = "rebuild errors must be handled to avoid stale cache state"]
    pub fn rebuild_from_fallback(&self) -> Result<(), SpillError> {
        let snapshot_guard = self.midx_snapshot.borrow();
        let Some(snapshot) = snapshot_guard.as_ref() else {
            self.ordinal.borrow_mut().take();
            return Ok(());
        };

        let midx = snapshot.view();
        self.rebuild_with_midx(&midx, snapshot)
    }

    /// Rebuilds the ordinal cache using a pre-parsed MIDX view, avoiding a
    /// redundant `MidxView::parse` when the caller already holds one.
    fn rebuild_with_midx(
        &self,
        midx: &MidxView<'_>,
        snapshot: &ConfiguredMidxSnapshot,
    ) -> Result<(), SpillError> {
        let mut bitset = MidxOrdinalBitset::new(midx.object_count(), snapshot.folded_fingerprint);
        // Per-OID galloping search with cursor reuse: amortized O(log(gap)) per
        // OID where gap is the ordinal distance between consecutive matches.
        // Total cost across all n seen OIDs is O(n * log(N/n)) in the average
        // case. A merge-join against the sorted OIDL chunk would be O(n + N)
        // but requires MIDX OIDL iteration support not yet available.
        let mut cursor = MidxCursor::default();
        let mut length_mismatches = 0u32;
        for oid in self.fallback.bitmap().seen_oids() {
            match midx.find_oid_sorted(&mut cursor, &oid) {
                Ok(Some(ordinal)) => bitset.set(ordinal),
                Ok(None) => {}
                Err(MidxError::InputOidLengthMismatch { .. }) => {
                    length_mismatches += 1;
                }
                Err(err) => return Err(err.into()),
            }
        }
        if length_mismatches > 0 {
            debug!(
                length_mismatches,
                object_count = midx.object_count(),
                "skipped OIDs with mismatched hash length during ordinal rebuild"
            );
        }

        *self.ordinal.borrow_mut() = Some(OrdinalCache {
            bitset,
            artifact_fingerprint: snapshot.artifact_fingerprint.clone(),
        });
        Ok(())
    }

    /// Reconstructs the MIDX view from cached offsets and ensures the ordinal
    /// cache is valid, rebuilding from the fallback bitmap if stale.
    ///
    /// Uses `from_layout` for zero-parse view reconstruction on the hot path.
    #[inline]
    fn ensure_cache_and_view<'a>(
        &self,
        snapshot: &'a ConfiguredMidxSnapshot,
    ) -> Result<MidxView<'a>, SpillError> {
        let midx = snapshot.view();
        let needs_rebuild = {
            let guard = self.ordinal.borrow();
            !guard
                .as_ref()
                .is_some_and(|c| c.artifact_fingerprint == snapshot.artifact_fingerprint)
        };
        if needs_rebuild {
            self.ordinal.borrow_mut().take();
            self.rebuild_with_midx(&midx, snapshot)?;
        }
        Ok(midx)
    }

    /// Clears the cached ordinal state while leaving the roaring fallback and
    /// configured MIDX snapshot untouched.
    pub fn clear_ordinal_cache(&self) {
        self.ordinal.borrow_mut().take();
    }

    /// Seeds the ordinal cache from a persisted `MidxOrdinalBitset` payload.
    ///
    /// Returns `Ok(true)` when the persisted payload matches the configured
    /// snapshot and was installed. Missing or stale payloads are reported as
    /// `Ok(false)` because the ordinal cache is a rebuildable optimization.
    pub fn load_persisted_ordinal(&self, bytes: &[u8]) -> Result<bool, OrdinalSeenError> {
        let snapshot_guard = self.midx_snapshot.borrow();
        let Some(snapshot) = snapshot_guard.as_ref() else {
            self.ordinal.borrow_mut().take();
            return Ok(false);
        };

        let bitset = MidxOrdinalBitset::deserialize(bytes)?;
        if bitset.midx_fingerprint() != &snapshot.folded_fingerprint {
            self.ordinal.borrow_mut().take();
            return Ok(false);
        }
        if bitset.object_count() != snapshot.view().object_count() {
            self.ordinal.borrow_mut().take();
            return Ok(false);
        }

        *self.ordinal.borrow_mut() = Some(OrdinalCache {
            bitset,
            artifact_fingerprint: snapshot.artifact_fingerprint.clone(),
        });
        Ok(true)
    }

    /// Serializes the current ordinal cache, rebuilding it from the roaring
    /// fallback if needed.
    pub fn persisted_ordinal_bytes(&self) -> Result<Option<Vec<u8>>, SpillError> {
        let snapshot_guard = self.midx_snapshot.borrow();
        let Some(snapshot) = snapshot_guard.as_ref() else {
            return Ok(None);
        };
        let midx = self.ensure_cache_and_view(snapshot)?;
        let _ = midx;
        Ok(self
            .ordinal
            .borrow()
            .as_ref()
            .map(|cache| cache.bitset.serialize()))
    }

    /// Marks a batch of OIDs as seen in the in-memory ordinal cache only.
    ///
    /// The roaring fallback is not mutated here; callers use this after a
    /// spill-stage durability write succeeds so the current process can dedupe
    /// repeated MIDX-resident OIDs within the same scan.
    pub fn mark_seen_batch(&self, oids: &[OidBytes]) -> Result<u32, SpillError> {
        if oids.is_empty() {
            return Ok(0);
        }
        let snapshot_guard = self.midx_snapshot.borrow();
        let Some(snapshot) = snapshot_guard.as_ref() else {
            return Ok(0);
        };
        let midx = self.ensure_cache_and_view(snapshot)?;
        let mut ordinal_guard = self.ordinal.borrow_mut();
        let Some(cache) = ordinal_guard.as_mut() else {
            return Ok(0);
        };
        cache
            .bitset
            .mark_seen_batch(&midx, oids)
            .map_err(Into::into)
    }
}

impl SeenBlobStore for HybridSeenStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }

        let snapshot_guard = self.midx_snapshot.borrow();
        let Some(snapshot) = snapshot_guard.as_ref() else {
            return self.fallback.batch_check_seen(oids);
        };
        // Reconstruct MidxView from cached layout (no parse, no allocation).
        let midx = self.ensure_cache_and_view(snapshot)?;

        let cache_guard = self.ordinal.borrow();
        let Some(cache) = cache_guard.as_ref() else {
            return self.fallback.batch_check_seen(oids);
        };

        let mut result = Vec::with_capacity(oids.len());
        // Track fallback-needed positions by index only (8 bytes each) instead
        // of copying 33-byte OidBytes structs. Per-element `contains()` on the
        // roaring bitmap handles the small fallback set efficiently.
        let mut fallback_indices: Vec<usize> = Vec::new();
        let mut cursor = MidxCursor::default();
        let oid_len = snapshot.layout.format.oid_len();

        // Process first OID outside the loop to eliminate the Option branch
        // on `prev_oid` from every subsequent iteration.
        let first_oid = &oids[0];
        let (first_seen, first_is_fallback) =
            match probe_ordinal(first_oid, oid_len, &midx, &cache.bitset, &mut cursor) {
                Ok(result) => result,
                Err(e) => {
                    drop(cache_guard);
                    return Err(e.into());
                }
            };
        result.push(first_seen);
        if first_is_fallback {
            fallback_indices.push(0);
        }
        let mut prev_oid = first_oid;
        let mut prev_seen = first_seen;
        let mut prev_was_fallback = first_is_fallback;

        for (idx, oid) in oids.iter().enumerate().skip(1) {
            if prev_oid > oid {
                // Input violates sorted contract. Fall back to per-element
                // binary search which handles arbitrary order correctly.
                debug!(
                    batch_size = oids.len(),
                    violation_index = idx,
                    "unsorted input detected in batch_check_seen, falling back to per-element search"
                );
                drop(cache_guard);
                return Ok(self.fallback.bitmap().batch_contains(oids));
            }
            if prev_oid == oid {
                if prev_was_fallback {
                    result.push(false);
                    fallback_indices.push(idx);
                } else {
                    result.push(prev_seen);
                }
                continue;
            }

            let (seen, is_fallback) =
                match probe_ordinal(oid, oid_len, &midx, &cache.bitset, &mut cursor) {
                    Ok(result) => result,
                    Err(e) => {
                        drop(cache_guard);
                        return Err(e.into());
                    }
                };
            result.push(seen);
            if is_fallback {
                fallback_indices.push(idx);
            }
            prev_oid = oid;
            prev_seen = seen;
            prev_was_fallback = is_fallback;
        }

        // Patch fallback positions with per-element roaring lookups.
        // The fallback set is expected to be small (loose objects outside the
        // MIDX), so O(k log n) binary searches are cheaper than assembling a
        // sorted Vec<OidBytes> for a batch merge-walk.
        if !fallback_indices.is_empty() {
            let bitmap = self.fallback.bitmap();
            for &pos in &fallback_indices {
                result[pos] = bitmap.contains(&oids[pos]);
            }
        }
        Ok(result)
    }

    fn configure_midx_snapshot(
        &self,
        midx_bytes: BytesView,
        object_format: ObjectFormat,
        artifact_fingerprint: RepoArtifactFingerprint,
    ) -> Result<(), SpillError> {
        Self::set_midx_snapshot(self, midx_bytes, object_format, artifact_fingerprint)
    }
}

/// Probes the ordinal bitset for a single OID via the MIDX cursor.
///
/// Returns `Ok((seen, is_fallback))`. When `is_fallback` is true, the OID was
/// not resolved through the MIDX (wrong OID length or not found) and the
/// caller must check the roaring fallback for a definitive answer.
///
/// Returns `Err` for MIDX corruption or structural errors that should not be
/// silently masked.
#[inline]
fn probe_ordinal(
    oid: &OidBytes,
    expected_oid_len: u8,
    midx: &MidxView<'_>,
    bitset: &MidxOrdinalBitset,
    cursor: &mut MidxCursor,
) -> Result<(bool, bool), MidxError> {
    if oid.len() != expected_oid_len {
        return Ok((false, true));
    }
    match midx.find_oid_sorted(cursor, oid) {
        Ok(Some(ordinal)) => Ok((bitset.test(ordinal), false)),
        Ok(None) | Err(MidxError::InputOidLengthMismatch { .. }) => Ok((false, true)),
        Err(e) => Err(e),
    }
}

fn validate_snapshot_format(
    fallback: &RoaringSeenStore,
    object_format: ObjectFormat,
) -> Result<(), SpillError> {
    let expected = fallback.bitmap().oid_len();
    let got = object_format.oid_len();
    if got != expected {
        return Err(SpillError::OidLengthMismatch { got, expected });
    }
    Ok(())
}

fn fold_artifact_fingerprint(fingerprint: &RepoArtifactFingerprint) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"scanner-git::hybrid-seen-store");
    hasher.update(&fingerprint.packs_hash);
    hasher.update(&fingerprint.idx_hash);
    *hasher.finalize().as_bytes()
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
        build_test_midx_from_values(&(0..object_count).collect::<Vec<_>>())
    }

    fn build_test_midx_from_values(values: &[u32]) -> Vec<u8> {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-0.pack");
        for &value in values {
            builder.add_object(oid_raw_from_u32(value), 0, value as u64);
        }
        builder.build()
    }

    fn test_fingerprint(tag: u8) -> RepoArtifactFingerprint {
        RepoArtifactFingerprint {
            packs_hash: [tag; 32],
            idx_hash: [tag.wrapping_add(1); 32],
        }
    }

    fn build_seen_bitmap(values: &[u32]) -> RoaringSeenBitmap {
        let mut bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        let oids: Vec<OidBytes> = values.iter().copied().map(oid_from_u32).collect();
        bitmap.insert_batch(&oids).expect("bitmap");
        bitmap
    }

    fn build_hybrid_store(
        seen_values: &[u32],
        midx_values: &[u32],
        fingerprint: RepoArtifactFingerprint,
    ) -> HybridSeenStore {
        HybridSeenStore::with_midx(
            RoaringSeenStore::new(build_seen_bitmap(seen_values)),
            BytesView::from_vec(build_test_midx_from_values(midx_values)),
            ObjectFormat::Sha1,
            fingerprint,
        )
        .expect("hybrid store")
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

    #[test]
    fn hybrid_seen_store_matches_roaring_for_midx_and_loose_queries() {
        let fingerprint = test_fingerprint(0x10);
        let store = build_hybrid_store(
            &[1, 3, 5, 9, 10],
            &[0, 1, 2, 3, 4, 5, 6, 7],
            fingerprint.clone(),
        );
        let probes = vec![
            oid_from_u32(1),
            oid_from_u32(2),
            oid_from_u32(3),
            oid_from_u32(5),
            oid_from_u32(9),
            oid_from_u32(10),
            oid_from_u32(11),
        ];

        assert!(store.ordinal.borrow().is_none());
        let actual = store.batch_check_seen(&probes).expect("hybrid query");
        let expected = store
            .fallback()
            .batch_check_seen(&probes)
            .expect("roaring query");

        assert_eq!(actual, expected);
        assert!(store.is_valid_for_fingerprint(&fingerprint));
        assert_eq!(
            store
                .ordinal
                .borrow()
                .as_ref()
                .expect("cache")
                .bitset
                .cardinality(),
            3
        );
    }

    #[test]
    fn hybrid_seen_store_degrades_to_roaring_without_midx_snapshot() {
        let store = HybridSeenStore::new(RoaringSeenStore::new(build_seen_bitmap(&[1, 9, 10])));
        let probes = vec![oid_from_u32(1), oid_from_u32(5), oid_from_u32(9)];

        let actual = store.batch_check_seen(&probes).expect("hybrid query");
        let expected = store
            .fallback()
            .batch_check_seen(&probes)
            .expect("roaring query");

        assert_eq!(actual, expected);
        assert!(store.ordinal.borrow().is_none());
    }

    #[test]
    fn hybrid_seen_store_rebuilds_after_snapshot_change() {
        let fingerprint_a = test_fingerprint(0x20);
        let fingerprint_b = test_fingerprint(0x21);
        let store =
            build_hybrid_store(&[1, 3, 9], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint_a.clone());
        let probes = vec![oid_from_u32(1), oid_from_u32(3), oid_from_u32(9)];

        assert_eq!(
            store.batch_check_seen(&probes).expect("initial query"),
            vec![true, true, true]
        );
        assert!(store.is_valid_for_fingerprint(&fingerprint_a));
        assert_eq!(
            store
                .ordinal
                .borrow()
                .as_ref()
                .expect("cache")
                .bitset
                .cardinality(),
            2
        );

        store
            .set_midx_snapshot(
                BytesView::from_vec(build_test_midx_from_values(&[0, 2, 3, 4, 5, 6, 7, 8])),
                ObjectFormat::Sha1,
                fingerprint_b.clone(),
            )
            .expect("replace midx");

        assert!(store.ordinal.borrow().is_none());
        assert!(!store.is_valid_for_fingerprint(&fingerprint_a));

        let actual = store.batch_check_seen(&probes).expect("rebuild query");
        let expected = store
            .fallback()
            .batch_check_seen(&probes)
            .expect("roaring query");

        assert_eq!(actual, expected);
        assert!(store.is_valid_for_fingerprint(&fingerprint_b));
        assert_eq!(
            store
                .ordinal
                .borrow()
                .as_ref()
                .expect("cache")
                .bitset
                .cardinality(),
            1
        );
    }

    #[test]
    fn hybrid_seen_store_invalidates_cache_before_fallback_mutation() {
        let fingerprint = test_fingerprint(0x30);
        let mut store = build_hybrid_store(&[1], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint.clone());
        let initial = vec![oid_from_u32(1), oid_from_u32(2)];

        assert_eq!(
            store.batch_check_seen(&initial).expect("initial query"),
            vec![true, false]
        );
        assert!(store.is_valid_for_fingerprint(&fingerprint));

        store
            .fallback_mut()
            .bitmap_mut()
            .insert_batch(&[oid_from_u32(2), oid_from_u32(9)])
            .expect("insert");
        assert!(store.ordinal.borrow().is_none());

        let probes = vec![oid_from_u32(1), oid_from_u32(2), oid_from_u32(9)];
        let actual = store.batch_check_seen(&probes).expect("updated query");
        let expected = store
            .fallback()
            .batch_check_seen(&probes)
            .expect("roaring query");

        assert_eq!(actual, expected);
        assert!(store.is_valid_for_fingerprint(&fingerprint));
        assert_eq!(
            store
                .ordinal
                .borrow()
                .as_ref()
                .expect("cache")
                .bitset
                .cardinality(),
            2
        );
    }

    #[test]
    fn hybrid_seen_store_marks_staged_midx_oids_without_mutating_roaring_fallback() {
        let fingerprint = test_fingerprint(0x31);
        let store = build_hybrid_store(&[], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint);
        let staged = oid_from_u32(3);

        assert_eq!(
            store
                .fallback()
                .batch_check_seen(&[staged])
                .expect("fallback query"),
            vec![false]
        );

        assert_eq!(
            store.mark_seen_batch(&[staged]).expect("mark staged oid"),
            1
        );
        assert_eq!(
            store.batch_check_seen(&[staged]).expect("hybrid query"),
            vec![true]
        );
        assert_eq!(
            store
                .fallback()
                .batch_check_seen(&[staged])
                .expect("fallback query"),
            vec![false]
        );
    }

    #[test]
    fn hybrid_seen_store_restores_matching_persisted_ordinal_cache() {
        let fingerprint = test_fingerprint(0x32);
        let store = build_hybrid_store(&[1, 3], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint.clone());
        let persisted = store
            .persisted_ordinal_bytes()
            .expect("serialize ordinal")
            .expect("ordinal bytes");

        let restored = build_hybrid_store(&[1, 3], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint.clone());
        assert!(
            restored
                .load_persisted_ordinal(&persisted)
                .expect("restore ordinal"),
            "matching fingerprint should restore the persisted cache"
        );
        assert!(restored.is_valid_for_fingerprint(&fingerprint));
        assert_eq!(
            restored
                .batch_check_seen(&[oid_from_u32(1), oid_from_u32(2), oid_from_u32(3)])
                .expect("restored query"),
            vec![true, false, true]
        );
    }

    #[test]
    fn hybrid_seen_store_discards_stale_persisted_ordinal_cache() {
        let fingerprint_a = test_fingerprint(0x33);
        let fingerprint_b = test_fingerprint(0x34);
        let store = build_hybrid_store(&[1, 3], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint_a);
        let persisted = store
            .persisted_ordinal_bytes()
            .expect("serialize ordinal")
            .expect("ordinal bytes");

        let restored =
            build_hybrid_store(&[1, 3], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint_b.clone());
        assert!(
            !restored
                .load_persisted_ordinal(&persisted)
                .expect("restore ordinal"),
            "stale fingerprint should discard the persisted cache"
        );
        assert!(!restored.is_valid_for_fingerprint(&fingerprint_b));
        assert_eq!(
            restored
                .batch_check_seen(&[oid_from_u32(1), oid_from_u32(2), oid_from_u32(3)])
                .expect("fallback rebuild query"),
            vec![true, false, true]
        );
    }

    #[test]
    fn hybrid_seen_store_falls_back_correctly_for_unsorted_input() {
        let fingerprint = test_fingerprint(0x50);
        let store = build_hybrid_store(&[1, 3, 5, 7], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint);
        // Deliberately unsorted probes.
        let probes = vec![
            oid_from_u32(5),
            oid_from_u32(3),
            oid_from_u32(1),
            oid_from_u32(7),
            oid_from_u32(9),
        ];

        let actual = store.batch_check_seen(&probes).expect("unsorted query");
        let expected: Vec<bool> = probes
            .iter()
            .map(|oid| store.fallback().bitmap().contains(oid))
            .collect();

        assert_eq!(actual, expected);
    }

    #[test]
    fn hybrid_seen_store_rejects_oid_format_mismatch() {
        let bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        let midx_bytes = build_test_midx(4);
        let err = HybridSeenStore::with_midx(
            RoaringSeenStore::new(bitmap),
            BytesView::from_vec(midx_bytes),
            ObjectFormat::Sha256,
            test_fingerprint(0x60),
        )
        .expect_err("format mismatch");
        assert!(
            matches!(
                err,
                SpillError::OidLengthMismatch {
                    got: 32,
                    expected: 20
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn hybrid_seen_store_clears_midx_snapshot_and_degrades() {
        let fingerprint = test_fingerprint(0x70);
        let store = build_hybrid_store(&[1, 3, 5], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint.clone());
        let probes = vec![oid_from_u32(1), oid_from_u32(3), oid_from_u32(5)];

        // Warm the ordinal cache.
        let _ = store.batch_check_seen(&probes).expect("warm query");
        assert!(store.is_valid_for_fingerprint(&fingerprint));

        // Clear and verify cache is gone.
        store.clear_midx_snapshot();
        assert!(store.ordinal.borrow().is_none());

        // Queries still work via roaring fallback.
        let actual = store.batch_check_seen(&probes).expect("post-clear query");
        let expected = store.fallback().batch_check_seen(&probes).expect("roaring");
        assert_eq!(actual, expected);
    }

    #[test]
    fn hybrid_seen_store_invalidates_cache_on_same_fingerprint_reset() {
        let fingerprint = test_fingerprint(0x80);
        let store = build_hybrid_store(&[1, 3], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint.clone());
        let probes = vec![oid_from_u32(1), oid_from_u32(3)];

        // Warm the ordinal cache.
        let _ = store.batch_check_seen(&probes).expect("warm query");
        assert!(store.ordinal.borrow().is_some());

        // Re-set snapshot with the same fingerprint.
        store
            .set_midx_snapshot(
                BytesView::from_vec(build_test_midx_from_values(&[0, 1, 2, 3, 4, 5, 6, 7])),
                ObjectFormat::Sha1,
                fingerprint.clone(),
            )
            .expect("re-set");

        // Cache must be invalidated even with the same fingerprint, because
        // RepoArtifactFingerprint hashes metadata, not content.
        assert!(store.ordinal.borrow().is_none());

        // Verify the cache rebuilds correctly on the next query.
        let actual = store.batch_check_seen(&probes).expect("post-reset query");
        assert_eq!(actual, vec![true, true]);
        assert!(store.is_valid_for_fingerprint(&fingerprint));
    }

    #[test]
    fn hybrid_seen_store_handles_duplicate_loose_oids_in_sorted_input() {
        let fingerprint = test_fingerprint(0x90);
        // MIDX covers [0..8], OID 9 is loose-only but present in roaring.
        let store = build_hybrid_store(&[1, 9], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint);
        // Sorted probes with consecutive duplicate of a loose OID.
        let probes = vec![oid_from_u32(9), oid_from_u32(9)];
        let actual = store.batch_check_seen(&probes).expect("duplicate loose");
        assert_eq!(actual, vec![true, true]);
    }

    #[test]
    fn hybrid_seen_store_handles_all_loose_batch_with_warm_cache() {
        let fingerprint = test_fingerprint(0x91);
        // MIDX covers [0..8], roaring has seen OIDs 9, 10, 11 (all loose).
        let store = build_hybrid_store(&[9, 10, 11], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint);

        // Warm the ordinal cache with a mixed query containing some MIDX OIDs.
        let warmup = vec![oid_from_u32(1), oid_from_u32(5), oid_from_u32(9)];
        let _ = store.batch_check_seen(&warmup).expect("warmup query");
        assert!(
            store.ordinal.borrow().is_some(),
            "cache must be populated after warmup"
        );

        // All probes are outside the MIDX range (sorted).
        let probes = vec![
            oid_from_u32(9),
            oid_from_u32(10),
            oid_from_u32(11),
            oid_from_u32(12),
        ];
        let actual = store.batch_check_seen(&probes).expect("all-loose query");
        assert_eq!(actual, vec![true, true, true, false]);

        // Oracle comparison via the fallback bitmap.
        let expected = store
            .fallback()
            .batch_check_seen(&probes)
            .expect("roaring query");
        assert_eq!(actual, expected);
    }

    #[test]
    fn hybrid_seen_store_handles_duplicate_midx_oids_in_sorted_input() {
        let fingerprint = test_fingerprint(0x92);
        // MIDX covers [0..8], roaring has seen OID 1 (MIDX-resident).
        let store = build_hybrid_store(&[1], &[0, 1, 2, 3, 4, 5, 6, 7], fingerprint);
        // Sorted duplicates of an MIDX-resident OID.
        let probes = vec![oid_from_u32(1), oid_from_u32(1)];
        let actual = store.batch_check_seen(&probes).expect("duplicate midx");
        assert_eq!(actual, vec![true, true]);
    }

    #[derive(Debug, Clone)]
    enum HybridOp {
        Insert(u16),
        Query(Vec<u16>),
        /// Queries without pre-sorting, exercising the unsorted-input fallback.
        QueryUnsorted(Vec<u16>),
        /// Replaces the MIDX snapshot with a shifted range, invalidating the
        /// ordinal cache without changing the roaring oracle.
        ChangeMidx,
    }

    fn hybrid_ops() -> impl Strategy<Value = Vec<HybridOp>> {
        vec(
            prop_oneof![
                5 => (0u16..96).prop_map(HybridOp::Insert),
                4 => vec(0u16..96, 0..16).prop_map(HybridOp::Query),
                2 => vec(0u16..96, 0..16).prop_map(HybridOp::QueryUnsorted),
                1 => Just(HybridOp::ChangeMidx),
            ],
            0..96,
        )
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

        #[test]
        fn hybrid_seen_store_matches_hashset_oracle_for_insert_query_sequences(
            ops in hybrid_ops(),
        ) {
            let mut oracle = std::collections::HashSet::new();
            let midx_values: Vec<u32> = (0..64).collect();
            let mut store = build_hybrid_store(&[], &midx_values, test_fingerprint(0x40));
            // Generation counter for producing distinct fingerprints after
            // ChangeMidx operations.
            let mut midx_gen: u8 = 0x40;

            for op in ops {
                match op {
                    HybridOp::Insert(value) => {
                        let oid = oid_from_u32(value as u32);
                        store
                            .fallback_mut()
                            .bitmap_mut()
                            .insert_batch(&[oid])
                            .expect("insert");
                        oracle.insert(oid);
                    }
                    HybridOp::Query(values) => {
                        let mut probes: Vec<OidBytes> =
                            values.into_iter().map(|value| oid_from_u32(value as u32)).collect();
                        probes.sort_unstable();
                        let expected: Vec<bool> =
                            probes.iter().map(|oid| oracle.contains(oid)).collect();
                        let actual = store.batch_check_seen(&probes).expect("query");
                        prop_assert_eq!(actual, expected);
                    }
                    HybridOp::QueryUnsorted(values) => {
                        // Deliberately unsorted probes to exercise the
                        // unsorted-input fallback path.
                        let probes: Vec<OidBytes> =
                            values.into_iter().map(|value| oid_from_u32(value as u32)).collect();
                        let actual = store.batch_check_seen(&probes).expect("unsorted query");
                        // Compare element-by-element since order matches
                        // input order, not sorted order.
                        for (got, oid) in actual.iter().zip(probes.iter()) {
                            let want = oracle.contains(oid);
                            prop_assert_eq!(*got, want);
                        }
                    }
                    HybridOp::ChangeMidx => {
                        // Shift the MIDX range to invalidate the ordinal
                        // cache. The oracle (HashSet) is unaffected.
                        midx_gen = midx_gen.wrapping_add(1);
                        let shifted: Vec<u32> = (32..96).collect();
                        store
                            .set_midx_snapshot(
                                BytesView::from_vec(build_test_midx_from_values(&shifted)),
                                ObjectFormat::Sha1,
                                test_fingerprint(midx_gen),
                            )
                            .expect("change midx");
                    }
                }
            }
        }
    }
}
