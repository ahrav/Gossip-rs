//! In-memory Bloom filter for done-ledger prefiltering.
//!
//! This wrapper accepts [`OvidHash`] keys directly while keeping the lookup
//! path allocation-free. Construction is intentionally gated:
//!
//! - scopes below [`DoneLedgerBloomFilter::MIN_THRESHOLD`] skip the filter
//!   because the fixed setup cost outweighs the benefit;
//! - scopes above [`DoneLedgerBloomFilter::MAX_BYTES`] skip the filter so the
//!   bitset stays within the configured memory budget.
//!
//! The done-ledger is monotonic, so a missing filter only causes extra
//! persistence lookups. It never causes an already-processed item to be
//! treated as new.
#![allow(dead_code)]

use std::{
    f64::consts::LN_2,
    hash::{BuildHasherDefault, Hasher},
    mem::size_of,
};

use fastbloom::BloomFilter;
use gossip_contracts::persistence::OvidHash;

type RawU64BuildHasher = BuildHasherDefault<RawU64Hasher>;
type InnerBloomFilter = BloomFilter<512, RawU64BuildHasher>;

/// In-memory Bloom filter keyed by [`OvidHash`].
///
/// The wrapper uses a pass-through `u64` hasher so the first 8 bytes of the
/// BLAKE3-derived `OvidHash` become the Bloom filter's base hash without an
/// extra hashing layer in steady-state lookups.
#[derive(Debug, Clone)]
pub(crate) struct DoneLedgerBloomFilter {
    inner: InnerBloomFilter,
    len: usize,
    memory_bytes: usize,
}

impl DoneLedgerBloomFilter {
    /// Skip Bloom construction for tiny scopes.
    pub(crate) const MIN_THRESHOLD: usize = 10_000;
    /// Cap Bloom memory at 32 MiB so the filter remains cache-friendly.
    pub(crate) const MAX_BYTES: usize = 32 * 1024 * 1024;
    /// Target false-positive rate used for sizing.
    pub(crate) const TARGET_FPR: f64 = 0.01;

    /// Construct an empty Bloom filter sized for `expected_items`.
    ///
    /// Returns `None` when the scope is too small to justify the filter or
    /// when the requested capacity would exceed the memory cap.
    pub(crate) fn new(expected_items: usize) -> Option<Self> {
        if expected_items < Self::MIN_THRESHOLD {
            return None;
        }

        let estimated_bytes = Self::estimated_memory_bytes(expected_items)?;
        if estimated_bytes > Self::MAX_BYTES {
            return None;
        }

        let inner = BloomFilter::with_false_pos(Self::TARGET_FPR)
            .hasher(RawU64BuildHasher::default())
            .expected_items(expected_items);
        let memory_bytes = inner.as_slice().len().checked_mul(size_of::<u64>())?;
        if memory_bytes > Self::MAX_BYTES {
            return None;
        }

        Some(Self {
            inner,
            len: 0,
            memory_bytes,
        })
    }

    /// Return `true` when the filter may contain `hash`.
    ///
    /// False positives are possible, but false negatives are not for keys that
    /// were previously inserted into this filter instance.
    #[inline]
    pub(crate) fn maybe_contains(&self, hash: &OvidHash) -> bool {
        self.inner.contains(&RawBloomWord(ovid_to_u64(hash)))
    }

    /// Insert `hash` into the filter.
    #[inline]
    pub(crate) fn insert(&mut self, hash: &OvidHash) {
        self.inner.insert(&RawBloomWord(ovid_to_u64(hash)));
        self.len = self.len.saturating_add(1);
    }

    /// Number of inserted keys recorded by this wrapper instance.
    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no keys have been inserted yet.
    #[inline]
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Heap memory reserved by the underlying Bloom bitset.
    #[inline]
    pub(crate) const fn memory_bytes(&self) -> usize {
        self.memory_bytes
    }

    fn estimated_memory_bytes(expected_items: usize) -> Option<usize> {
        let bits = Self::estimated_num_bits(expected_items)?;
        bits.checked_add(7)?.checked_div(8)
    }

    fn estimated_num_bits(expected_items: usize) -> Option<usize> {
        let items = expected_items as f64;
        let bits = (-items * Self::TARGET_FPR.ln() / (LN_2 * LN_2)).ceil();
        if !bits.is_finite() || bits > usize::MAX as f64 {
            return None;
        }
        Some((bits as usize).max(512))
    }
}

#[inline]
fn ovid_to_u64(hash: &OvidHash) -> u64 {
    let first8: [u8; 8] = hash.as_bytes()[..8]
        .try_into()
        .expect("OvidHash always contains 32 bytes");
    u64::from_le_bytes(first8)
}

#[derive(Clone, Copy, Debug, Default)]
struct RawU64Hasher(u64);

impl Hasher for RawU64Hasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut state = 0xcbf29ce484222325u64;
        for &byte in bytes {
            state ^= u64::from(byte);
            state = state.wrapping_mul(0x100000001b3);
        }
        self.0 = state;
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RawBloomWord(u64);

impl std::hash::Hash for RawBloomWord {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gossip_contracts::{
        identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, TenantId},
        persistence::{
            CommitHandle, DoneLedger, DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance,
            DoneLedgerRecord, DoneLedgerStatus,
        },
    };
    use gossip_persistence_inmemory::InMemoryDoneLedger;
    use proptest::prelude::*;

    fn splitmix64(mut value: u64) -> u64 {
        value = value.wrapping_add(0x9e3779b97f4a7c15);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        value ^ (value >> 31)
    }

    fn ovid(seed: u64) -> OvidHash {
        let mut bytes = [0u8; 32];
        for (index, chunk) in bytes.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&splitmix64(seed.wrapping_add(index as u64)).to_le_bytes());
        }
        OvidHash::from_bytes(bytes)
    }

    fn tenant(seed: u8) -> TenantId {
        TenantId::from_bytes([seed; 32])
    }

    fn policy(seed: u8) -> PolicyHash {
        PolicyHash::from_bytes([seed; 32])
    }

    fn provenance(run: u64) -> DoneLedgerProvenance {
        DoneLedgerProvenance::new(
            RunId::from_raw(run),
            ShardId::from_raw(run + 1),
            FenceEpoch::from_raw(run + 2),
            LogicalTime::from_raw(run + 3),
            LogicalTime::from_raw(run + 4),
        )
    }

    fn scanned_record(
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        ovid_hash: OvidHash,
    ) -> DoneLedgerRecord {
        DoneLedgerRecord::try_new(
            DoneLedgerKey::new(tenant_id, policy_hash, ovid_hash),
            DoneLedgerStatus::ScannedClean,
            128,
            0,
            provenance(10),
            None,
        )
        .expect("scanned record should be valid")
    }

    fn retryable_record(
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        ovid_hash: OvidHash,
    ) -> DoneLedgerRecord {
        DoneLedgerRecord::try_new(
            DoneLedgerKey::new(tenant_id, policy_hash, ovid_hash),
            DoneLedgerStatus::FailedRetryable,
            64,
            0,
            provenance(20),
            Some(DoneLedgerErrorCode::try_new("RETRYABLE").expect("error code should be valid")),
        )
        .expect("retryable record should be valid")
    }

    #[test]
    fn empty_filter_returns_false() {
        let filter = DoneLedgerBloomFilter::new(DoneLedgerBloomFilter::MIN_THRESHOLD)
            .expect("threshold-sized filter should be constructed");

        assert!(!filter.maybe_contains(&ovid(1)));
        assert!(filter.is_empty());
    }

    #[test]
    fn inserted_keys_always_return_true() {
        let mut filter = DoneLedgerBloomFilter::new(DoneLedgerBloomFilter::MIN_THRESHOLD)
            .expect("threshold-sized filter should be constructed");

        for seed in 0..256 {
            let hash = ovid(seed);
            filter.insert(&hash);
            assert!(filter.maybe_contains(&hash));
        }

        assert_eq!(filter.len(), 256);
        assert!(filter.memory_bytes() <= DoneLedgerBloomFilter::MAX_BYTES);
    }

    #[test]
    fn below_threshold_returns_none() {
        assert!(DoneLedgerBloomFilter::new(DoneLedgerBloomFilter::MIN_THRESHOLD - 1).is_none());
        assert!(DoneLedgerBloomFilter::new(DoneLedgerBloomFilter::MIN_THRESHOLD).is_some());
    }

    #[test]
    fn above_cap_returns_none() {
        assert!(DoneLedgerBloomFilter::new(30_000_000).is_none());
    }

    #[test]
    fn feedback_committed_keys_become_positive() {
        let hash = ovid(42);
        let mut filter = DoneLedgerBloomFilter::new(DoneLedgerBloomFilter::MIN_THRESHOLD)
            .expect("threshold-sized filter should be constructed");

        assert!(!filter.maybe_contains(&hash));
        filter.insert(&hash);

        assert!(filter.maybe_contains(&hash));
        assert_eq!(filter.len(), 1);
        assert!(!filter.is_empty());
    }

    #[test]
    fn fpr_within_target_at_100k_items() {
        const INSERTED: u64 = 100_000;
        const PROBES: u64 = 50_000;

        let mut filter = DoneLedgerBloomFilter::new(INSERTED as usize)
            .expect("100k-item filter should fit within the memory cap");
        for seed in 0..INSERTED {
            filter.insert(&ovid(seed));
        }

        let false_positives = (INSERTED..INSERTED + PROBES)
            .filter(|seed| filter.maybe_contains(&ovid(*seed)))
            .count();
        let sample_fpr = false_positives as f64 / PROBES as f64;

        assert!(
            sample_fpr <= 0.03,
            "sample false-positive rate {sample_fpr:.4} exceeded the 3% ceiling"
        );
    }

    #[test]
    fn bulk_load_from_done_ledger_roundtrips() {
        let ledger = InMemoryDoneLedger::new();
        let tenant_id = tenant(7);
        let policy_hash = policy(9);
        let terminal_hash = ovid(100);
        let retryable_hash = ovid(200);

        let handle = ledger
            .batch_upsert(&[
                scanned_record(tenant_id, policy_hash, terminal_hash),
                retryable_record(tenant_id, policy_hash, retryable_hash),
            ])
            .expect("upsert should succeed");
        handle.wait().expect("upsert should become durable");

        let hashes = ledger
            .list_done_hashes(tenant_id, policy_hash)
            .expect("bulk load should succeed");
        let actual: std::collections::HashSet<_> = hashes.iter().copied().collect();
        let expected = std::collections::HashSet::from([terminal_hash]);
        assert_eq!(actual, expected);

        let mut filter = DoneLedgerBloomFilter::new(DoneLedgerBloomFilter::MIN_THRESHOLD)
            .expect("threshold-sized filter should be constructed");
        for hash in &hashes {
            filter.insert(hash);
        }

        assert!(filter.maybe_contains(&terminal_hash));
        assert!(!filter.maybe_contains(&retryable_hash));
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            .. ProptestConfig::default()
        })]

        #[test]
        fn no_false_negatives(keys in proptest::collection::vec(any::<[u8; 32]>(), 0..256)) {
            let mut filter = DoneLedgerBloomFilter::new(
                DoneLedgerBloomFilter::MIN_THRESHOLD.max(keys.len())
            ).expect("filter should be constructed for the requested capacity");

            let hashes: Vec<_> = keys.into_iter().map(OvidHash::from_bytes).collect();
            for hash in &hashes {
                filter.insert(hash);
            }

            for hash in &hashes {
                prop_assert!(filter.maybe_contains(hash));
            }
        }
    }
}
