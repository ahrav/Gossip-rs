//! Fixed-capacity OID index for fast OID -> MIDX index lookups.
//!
//! This is a simple open-addressing hash table with linear probing and a
//! fixed load factor. It is optimized for OID workloads where keys are
//! uniformly distributed (SHA-1/SHA-256), enabling predictable O(1) lookups
//! without per-lookup allocations.
//!
//! # Invariants
//! - Table capacity is a power of two and `mask = capacity - 1`.
//! - Empty slots use `NONE_U32` as the sentinel value.
//! - `len <= capacity * LOAD_FACTOR` (enforced at build time).
//!
//! # Performance
//! - Insert and lookup are O(1) expected time with linear probing.
//! - A single-byte hash tag avoids full-key compares on most misses.

use super::midx::MidxView;
use super::object_id::OidBytes;

/// Sentinel value for empty slots.
const NONE_U32: u32 = u32::MAX;
/// Load factor numerator (e.g. 7/10 = 0.7).
const LOAD_FACTOR_NUM: usize = 7;
/// Load factor denominator.
const LOAD_FACTOR_DEN: usize = 10;

#[derive(Clone, Copy, Debug)]
struct Entry {
    key: OidBytes,
    value: u32,
    tag: u8,
}

impl Entry {
    #[inline]
    fn empty() -> Self {
        Self {
            key: OidBytes::default(),
            value: NONE_U32,
            tag: 0,
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.value == NONE_U32
    }
}

/// OID index with fixed capacity and open addressing.
#[derive(Debug)]
pub struct OidIndex {
    entries: Vec<Entry>,
    mask: usize,
    oid_len: u8,
    len: u32,
}

impl OidIndex {
    /// Builds an index for the OIDs stored in the MIDX.
    pub fn from_midx(midx: &MidxView<'_>) -> Self {
        let count = midx.object_count() as usize;
        let capacity = table_size_for_count(count);
        let mut index = Self {
            entries: vec![Entry::empty(); capacity],
            mask: capacity - 1,
            oid_len: midx.oid_len(),
            len: 0,
        };

        for idx in 0..midx.object_count() {
            let oid = OidBytes::from_slice(midx.oid_at(idx));
            index.insert(oid, idx);
        }

        index
    }

    /// Returns the number of entries stored.
    #[inline]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Returns true if the index is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the OID length this index was built for.
    #[inline]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }

    /// Returns the underlying table size (power of two).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }

    /// Looks up the MIDX index for the given OID.
    #[inline]
    pub fn get(&self, oid: &OidBytes) -> Option<u32> {
        debug_assert_eq!(oid.len(), self.oid_len, "OID length mismatch");
        let hash = hash_oid(oid);
        let tag = (hash >> 56) as u8;
        let mut slot = (hash as usize) & self.mask;

        for _ in 0..self.entries.len() {
            let entry = &self.entries[slot];
            if entry.is_empty() {
                return None;
            }
            if entry.tag == tag && entry.key == *oid {
                return Some(entry.value);
            }
            slot = (slot + 1) & self.mask;
        }

        None
    }

    fn insert(&mut self, oid: OidBytes, value: u32) {
        debug_assert_eq!(oid.len(), self.oid_len, "OID length mismatch");
        let hash = hash_oid(&oid);
        let tag = (hash >> 56) as u8;
        let mut slot = (hash as usize) & self.mask;

        for _ in 0..self.entries.len() {
            let entry = &mut self.entries[slot];
            if entry.is_empty() {
                entry.key = oid;
                entry.value = value;
                entry.tag = tag;
                self.len += 1;
                return;
            }
            if entry.tag == tag && entry.key == oid {
                return;
            }
            slot = (slot + 1) & self.mask;
        }

        unreachable!("oid index capacity exceeded; load factor too high");
    }
}

fn table_size_for_count(count: usize) -> usize {
    let min_capacity = count
        .saturating_mul(LOAD_FACTOR_DEN)
        .div_ceil(LOAD_FACTOR_NUM);
    min_capacity.max(1).next_power_of_two()
}

/// Hash an OID using head/tail bytes to avoid full-key mixing.
#[inline]
fn hash_oid(oid: &OidBytes) -> u64 {
    let bytes = oid.as_slice();
    let head = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let tail = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
    let mut h = head ^ tail.rotate_left(32);
    h ^= (bytes.len() as u64) << 56;
    mix64(h)
}

#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::midx::MidxView;
    use crate::object_id::ObjectFormat;

    use super::super::midx_test_builder::MidxBuilder;

    #[test]
    fn oid_index_matches_midx_lookup() {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-a");
        builder.add_pack(b"pack-b");

        builder.add_object([0x11; 20], 0, 100);
        builder.add_object([0x22; 20], 1, 200);
        builder.add_object([0x33; 20], 1, 300);

        let data = builder.build();
        let midx = MidxView::parse(&data, ObjectFormat::Sha1).unwrap();
        let index = OidIndex::from_midx(&midx);

        for idx in 0..midx.object_count() {
            let oid = OidBytes::from_slice(midx.oid_at(idx));
            assert_eq!(index.get(&oid), Some(idx));
        }

        let missing = OidBytes::sha1([0x44; 20]);
        assert_eq!(index.get(&missing), None);
    }
}
