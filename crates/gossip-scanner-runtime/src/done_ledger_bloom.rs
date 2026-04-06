//! Bloom-backed done-ledger prefiltering helpers.
//!
//! [`DoneLedgerBloomFilter`] stores terminal [`OvidHash`] keys in a compact
//! in-memory Bloom filter sized at worker startup. [`BloomFilteredDoneLedger`]
//! wraps any [`DoneLedger`] implementation and uses that filter to short-circuit
//! `batch_get` lookups for keys that are definitely absent.
//!
//! Construction is intentionally gated:
//!
//! - scopes below [`DoneLedgerBloomFilter::MIN_THRESHOLD`] skip the filter
//!   because the fixed setup cost outweighs the benefit;
//! - scopes whose estimated Bloom memory would exceed
//!   [`DoneLedgerBloomFilter::MAX_BYTES`] skip the filter to stay within the
//!   configured memory budget.
//!
//! The filter itself is immutable after construction. A shared invalidation bit
//! disables prefiltering after the first successful `batch_upsert` accepted by
//! any clone, preserving the `DoneLedger` contract for newly written keys
//! without adding lock contention to the read path.

use std::{
    f64::consts::LN_2,
    fmt,
    hash::{BuildHasherDefault, Hasher},
    mem::size_of,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use fastbloom::BloomFilter;
use gossip_contracts::{
    identity::{PolicyHash, TenantId},
    persistence::{DoneLedger, DoneLedgerRecord, OvidHash},
};

type RawU64BuildHasher = BuildHasherDefault<RawU64Hasher>;
// 512-bit blocks: widest SIMD path in fastbloom (two u64x4 sparse-hash rounds
// per `contains` call).
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

/// Done-ledger decorator that prunes definitely-absent keys before `batch_get`
/// reaches the backing store.
///
/// The decorator bulk-loads terminal keys once at COLD tier from
/// `DoneLedger::list_done_hashes` and then uses the resulting Bloom filter on
/// every `batch_get`. Bloom-negative keys are known absent and return `None`
/// without touching the inner backend; Bloom-positive keys are delegated to the
/// wrapped ledger so false positives remain safe.
///
/// `batch_upsert` never mutates the filter. Instead, a shared invalidation bit
/// disables prefiltering after the first successful write accepted by any
/// clone. That keeps newly written keys visible to subsequent `batch_get`
/// calls while avoiding per-key feedback plumbing or lock contention.
#[derive(Clone)]
pub(crate) struct BloomFilteredDoneLedger<D> {
    inner: D,
    /// Shared across clones so the immutable bitset is never deep-copied.
    filter: Option<Arc<DoneLedgerBloomFilter>>,
    /// Monotonic latch: transitions `false` to `true` exactly once, never reverts.
    ///
    /// The `Release` store in `batch_upsert` / `Acquire` load in `batch_get`
    /// pair is safe under the assumption that data written by the inner
    /// backend's `batch_upsert` is visible to subsequent `batch_get` calls on
    /// any clone *before* `batch_upsert` returns `Ok(handle)`. Both the
    /// in-memory and PostgreSQL backends satisfy this (synchronous
    /// [`ReadyCommitHandle`]). Backends with deferred visibility (data not
    /// readable until [`CommitHandle::wait`]) would require invalidation to be
    /// deferred to the commit handle.
    invalidate_prefilter: Arc<AtomicBool>,
}

impl<D: fmt::Debug> fmt::Debug for BloomFilteredDoneLedger<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BloomFilteredDoneLedger")
            .field("inner", &self.inner)
            .field("filter_enabled", &self.filter.is_some())
            .field(
                "invalidate_prefilter",
                &self.invalidate_prefilter.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl DoneLedgerBloomFilter {
    /// Skip Bloom construction for tiny scopes.
    pub(crate) const MIN_THRESHOLD: usize = 10_000;
    /// Cap Bloom memory at 32 MiB to bound per-scope prefilter overhead.
    pub(crate) const MAX_BYTES: usize = 32 * 1024 * 1024;
    /// Target false-positive rate used for sizing.
    pub(crate) const TARGET_FPR: f64 = 0.01;

    /// Construct an empty Bloom filter sized for `expected_items`.
    ///
    /// Callers must pass the full lifetime population the filter should cover.
    /// Returning `None` disables prefiltering for scopes where the setup cost
    /// or memory budget would outweigh the benefit.
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
        // The library may round the bitset up to the next block boundary, so
        // check the actual allocation before enabling the filter.
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
    /// False positives are possible, but false negatives are not for keys
    /// inserted into this filter instance.
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

    /// Number of insertions performed on this filter instance.
    ///
    /// Counts each `insert` call, including duplicates. This is a diagnostic
    /// counter and does not affect Bloom filter membership semantics.
    #[cfg(test)]
    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no keys have been inserted yet.
    #[cfg(test)]
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

    /// Return `true` when `count` falls within the viable range for Bloom
    /// construction: at or above [`MIN_THRESHOLD`](Self::MIN_THRESHOLD) and
    /// with estimated memory at or below [`MAX_BYTES`](Self::MAX_BYTES).
    ///
    /// Used by [`BloomFilteredDoneLedger::from_ledger`] to pre-check before
    /// materializing the full key set.
    pub(crate) fn is_viable_count(count: usize) -> bool {
        if count < Self::MIN_THRESHOLD {
            return false;
        }
        match Self::estimated_memory_bytes(count) {
            Some(bytes) => bytes <= Self::MAX_BYTES,
            None => false,
        }
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

impl<D> BloomFilteredDoneLedger<D> {
    /// Build a decorator from preloaded terminal done-ledger hashes.
    ///
    /// Returns a passthrough wrapper when the scope is too small for a useful
    /// Bloom filter or the estimated filter memory would exceed the cap.
    pub(crate) fn from_hashes(inner: D, done_hashes: &[OvidHash]) -> Self {
        let filter = DoneLedgerBloomFilter::new(done_hashes.len()).map(|mut filter| {
            for hash in done_hashes {
                filter.insert(hash);
            }
            Arc::new(filter)
        });
        Self {
            inner,
            filter,
            invalidate_prefilter: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Wrap `inner` without a Bloom filter so all calls delegate directly.
    pub(crate) fn passthrough(inner: D) -> Self {
        Self {
            inner,
            filter: None,
            invalidate_prefilter: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Build a decorator by bulk-loading terminal hashes from the inner
    /// done-ledger.
    ///
    /// Calls [`DoneLedger::count_done_hashes`] first when the backend
    /// supports cheap counting. If the scope falls outside the viable range
    /// (`< MIN_THRESHOLD` or estimated filter memory `> MAX_BYTES`), the
    /// decorator skips `list_done_hashes` entirely and returns a passthrough
    /// wrapper — avoiding the potentially multi-gigabyte transient allocation.
    ///
    /// When the backend returns `Ok(None)` for the count (no cheap counting),
    /// the method falls through to [`DoneLedger::list_done_hashes`] and
    /// delegates to [`from_hashes`](Self::from_hashes). When the scope is too
    /// small for a useful Bloom filter, the estimated memory would exceed the
    /// cap, or enumeration fails, the result is a passthrough wrapper.
    pub(crate) fn from_ledger(
        done_ledger: D,
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        worker_kind: &'static str,
    ) -> Self
    where
        D: DoneLedger,
        D::Error: std::error::Error + Send + Sync + 'static,
    {
        // Pre-check: if the backend supports cheap counting, bail out early
        // when the scope is outside the viable range. This avoids a
        // potentially multi-GiB transient allocation for scopes that would
        // be rejected by from_hashes anyway.
        match done_ledger.count_done_hashes(tenant_id, policy_hash) {
            Ok(Some(count)) => {
                if !DoneLedgerBloomFilter::is_viable_count(count) {
                    tracing::debug!(
                        worker_kind,
                        bloom_prefilter = "skipped",
                        done_hash_count = count,
                        min_threshold = DoneLedgerBloomFilter::MIN_THRESHOLD,
                        max_bytes = DoneLedgerBloomFilter::MAX_BYTES,
                        "done-ledger Bloom prefilter skipped via count pre-check; \
                         using passthrough mode"
                    );
                    return Self::passthrough(done_ledger);
                }
            }
            Ok(None) => {
                // Backend does not support cheap counting; fall through to
                // full enumeration.
            }
            Err(error) => {
                tracing::debug!(
                    worker_kind,
                    bloom_prefilter = "count_error",
                    error = %error,
                    "done-ledger count pre-check failed; falling through to enumeration"
                );
                // Non-fatal: proceed with the full list_done_hashes path.
            }
        }

        match done_ledger.list_done_hashes(tenant_id, policy_hash) {
            Ok(done_hashes) => {
                let decorated = Self::from_hashes(done_ledger, &done_hashes);
                if decorated.has_filter() {
                    tracing::info!(
                        worker_kind,
                        bloom_prefilter = "active",
                        done_hashes = done_hashes.len(),
                        filter_bytes = decorated.filter_memory_bytes().unwrap_or_default(),
                        "done-ledger Bloom prefilter enabled"
                    );
                } else {
                    tracing::debug!(
                        worker_kind,
                        bloom_prefilter = "inactive",
                        done_hashes = done_hashes.len(),
                        min_threshold = DoneLedgerBloomFilter::MIN_THRESHOLD,
                        max_bytes = DoneLedgerBloomFilter::MAX_BYTES,
                        "done-ledger Bloom prefilter inactive; using passthrough mode"
                    );
                }
                decorated
            }
            Err(error) => {
                tracing::error!(
                    worker_kind,
                    %tenant_id,
                    %policy_hash,
                    bloom_prefilter = "error",
                    error = %error,
                    "done-ledger Bloom prefilter unavailable; \
                     worker will proceed without prefiltering for this entire run"
                );
                Self::passthrough(done_ledger)
            }
        }
    }

    pub(crate) fn has_filter(&self) -> bool {
        self.filter.is_some()
    }

    pub(crate) fn filter_memory_bytes(&self) -> Option<usize> {
        self.filter.as_ref().map(|f| f.memory_bytes())
    }
}

impl<D> DoneLedger for BloomFilteredDoneLedger<D>
where
    D: DoneLedger,
{
    type Error = D::Error;
    type CommitHandle = D::CommitHandle;

    /// Returns rows aligned with `ovid_hashes`, skipping backend I/O for keys
    /// the Bloom filter proves absent.
    fn batch_get(
        &self,
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        ovid_hashes: &[OvidHash],
    ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
        let Some(filter) = &self.filter else {
            return self.inner.batch_get(tenant_id, policy_hash, ovid_hashes);
        };
        if self.invalidate_prefilter.load(Ordering::Acquire) {
            return self.inner.batch_get(tenant_id, policy_hash, ovid_hashes);
        }
        if ovid_hashes.is_empty() {
            return Ok(Vec::new());
        }

        let mut positive_indices = Vec::with_capacity(ovid_hashes.len());
        let mut positive_hashes = Vec::with_capacity(ovid_hashes.len());
        for (index, hash) in ovid_hashes.iter().copied().enumerate() {
            if filter.maybe_contains(&hash) {
                positive_indices.push(index);
                positive_hashes.push(hash);
            }
        }

        if positive_hashes.is_empty() {
            return Ok(vec![None; ovid_hashes.len()]);
        }
        if positive_hashes.len() == ovid_hashes.len() {
            return self.inner.batch_get(tenant_id, policy_hash, ovid_hashes);
        }

        let delegated = self
            .inner
            .batch_get(tenant_id, policy_hash, &positive_hashes)?;
        if delegated.len() != positive_indices.len() {
            debug_assert_eq!(
                delegated.len(),
                positive_indices.len(),
                "BloomFilteredDoneLedger inner batch_get violated positional contract"
            );
            tracing::error!(
                %tenant_id,
                %policy_hash,
                expected = positive_indices.len(),
                actual = delegated.len(),
                original_batch_size = ovid_hashes.len(),
                "inner DoneLedger batch_get violated positional contract; \
                 Bloom prefilter permanently disabled for this scope"
            );
            // Permanently disable prefiltering so subsequent calls delegate
            // directly instead of repeating the detect-and-retry cycle.
            self.invalidate_prefilter.store(true, Ordering::Release);
            return self.inner.batch_get(tenant_id, policy_hash, ovid_hashes);
        }

        let mut results = vec![None; ovid_hashes.len()];
        for (record, index) in delegated.into_iter().zip(positive_indices) {
            results[index] = record;
        }
        Ok(results)
    }

    /// Delegates writes directly and disables prefiltering for later reads once
    /// the inner backend accepts a non-empty batch.
    ///
    /// The invalidation bit is set after `inner.batch_upsert` returns `Ok` but
    /// before the caller invokes [`CommitHandle::wait`]. If `wait` subsequently
    /// fails the filter is disabled for writes that were never durable — a
    /// performance-only penalty (extra backend lookups, never incorrect results).
    /// The PostgreSQL backend uses synchronous [`ReadyCommitHandle`] where
    /// `wait` cannot fail after `batch_upsert` succeeds; the in-memory backend
    /// can simulate deferred or failing waits in fault-injection mode, but the
    /// early invalidation remains a safe performance fallback in that case.
    fn batch_upsert(
        &self,
        records: &[DoneLedgerRecord],
    ) -> Result<Self::CommitHandle, Self::Error> {
        let handle = self.inner.batch_upsert(records)?;
        if !records.is_empty() {
            self.invalidate_prefilter.store(true, Ordering::Release);
        }
        Ok(handle)
    }

    /// Delegates terminal-key enumeration without consulting the Bloom filter.
    fn list_done_hashes(
        &self,
        tenant_id: TenantId,
        policy_hash: PolicyHash,
    ) -> Result<Vec<OvidHash>, Self::Error> {
        self.inner.list_done_hashes(tenant_id, policy_hash)
    }

    /// Delegates terminal-key counting without consulting the Bloom filter.
    fn count_done_hashes(
        &self,
        tenant_id: TenantId,
        policy_hash: PolicyHash,
    ) -> Result<Option<usize>, Self::Error> {
        self.inner.count_done_hashes(tenant_id, policy_hash)
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
    fn write(&mut self, _bytes: &[u8]) {
        unimplemented!(
            "RawU64Hasher is a pass-through hasher for pre-hashed u64 values; \
             only write_u64 is supported"
        );
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

    use std::{
        collections::{HashMap, HashSet},
        io,
        sync::{Arc, Mutex},
    };

    use gossip_contracts::{
        identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, TenantId},
        persistence::{
            CommitHandle, DoneLedger, DoneLedgerCommitReceipt, DoneLedgerErrorCode, DoneLedgerKey,
            DoneLedgerProvenance, DoneLedgerRecord, DoneLedgerStatus, ReadyCommitHandle,
            run_done_ledger_conformance,
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
        let record = DoneLedgerRecord::try_new(
            DoneLedgerKey::new(tenant_id, policy_hash, ovid_hash),
            DoneLedgerStatus::ScannedClean,
            128,
            0,
            provenance(10),
            None,
        )
        .expect("scanned record should be valid");
        record.validate().expect("scanned record invariants");
        record
    }

    fn retryable_record(
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        ovid_hash: OvidHash,
    ) -> DoneLedgerRecord {
        let record = DoneLedgerRecord::try_new(
            DoneLedgerKey::new(tenant_id, policy_hash, ovid_hash),
            DoneLedgerStatus::FailedRetryable,
            64,
            0,
            provenance(20),
            Some(DoneLedgerErrorCode::try_new("RETRYABLE").expect("error code should be valid")),
        )
        .expect("retryable record should be valid");
        record.validate().expect("retryable record invariants");
        record
    }

    fn activated_hashes(primary: &[OvidHash]) -> Vec<OvidHash> {
        let mut hashes = Vec::new();
        let mut seen = HashSet::new();
        for &hash in primary {
            if seen.insert(hash) {
                hashes.push(hash);
            }
        }
        let mut seed = 1_000_000_u64;
        while hashes.len() < DoneLedgerBloomFilter::MIN_THRESHOLD {
            let hash = ovid(seed);
            seed = seed.wrapping_add(1);
            if seen.insert(hash) {
                hashes.push(hash);
            }
        }
        hashes
    }

    fn built_filter(done_hashes: &[OvidHash]) -> DoneLedgerBloomFilter {
        let mut filter =
            DoneLedgerBloomFilter::new(done_hashes.len()).expect("activated filter should build");
        for hash in done_hashes {
            filter.insert(hash);
        }
        filter
    }

    fn first_negative_hash(filter: &DoneLedgerBloomFilter, start_seed: u64) -> OvidHash {
        let mut seed = start_seed;
        loop {
            let candidate = ovid(seed);
            if !filter.maybe_contains(&candidate) {
                return candidate;
            }
            seed = seed.wrapping_add(1);
        }
    }

    #[derive(Clone, Debug)]
    struct TrackingDoneLedger {
        records: HashMap<OvidHash, DoneLedgerRecord>,
        batch_get_calls: Arc<Mutex<Vec<Vec<OvidHash>>>>,
        batch_upsert_calls: Arc<Mutex<Vec<Vec<DoneLedgerRecord>>>>,
        list_done_hashes_calls: Arc<Mutex<Vec<(TenantId, PolicyHash)>>>,
    }

    impl TrackingDoneLedger {
        fn with_records(records: impl IntoIterator<Item = DoneLedgerRecord>) -> Self {
            Self {
                records: records
                    .into_iter()
                    .map(|record| (record.key().ovid_hash(), record))
                    .collect(),
                batch_get_calls: Arc::new(Mutex::new(Vec::new())),
                batch_upsert_calls: Arc::new(Mutex::new(Vec::new())),
                list_done_hashes_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn empty() -> Self {
            Self::with_records(std::iter::empty::<DoneLedgerRecord>())
        }

        fn batch_get_calls(&self) -> Vec<Vec<OvidHash>> {
            self.batch_get_calls
                .lock()
                .expect("batch_get_calls lock")
                .clone()
        }

        fn batch_upsert_calls(&self) -> Vec<Vec<DoneLedgerRecord>> {
            self.batch_upsert_calls
                .lock()
                .expect("batch_upsert_calls lock")
                .clone()
        }

        fn list_done_hashes_calls(&self) -> Vec<(TenantId, PolicyHash)> {
            self.list_done_hashes_calls
                .lock()
                .expect("list_done_hashes_calls lock")
                .clone()
        }
    }

    impl DoneLedger for TrackingDoneLedger {
        type Error = io::Error;
        type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, io::Error>;

        fn batch_get(
            &self,
            _tenant_id: TenantId,
            _policy_hash: PolicyHash,
            ovid_hashes: &[OvidHash],
        ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
            self.batch_get_calls
                .lock()
                .expect("batch_get_calls lock")
                .push(ovid_hashes.to_vec());
            Ok(ovid_hashes
                .iter()
                .map(|ovid_hash| self.records.get(ovid_hash).cloned())
                .collect())
        }

        fn batch_upsert(
            &self,
            records: &[DoneLedgerRecord],
        ) -> Result<Self::CommitHandle, Self::Error> {
            self.batch_upsert_calls
                .lock()
                .expect("batch_upsert_calls lock")
                .push(records.to_vec());
            Ok(ReadyCommitHandle::ok(DoneLedgerCommitReceipt::new(0, 0, 0)))
        }

        fn list_done_hashes(
            &self,
            tenant_id: TenantId,
            policy_hash: PolicyHash,
        ) -> Result<Vec<OvidHash>, Self::Error> {
            self.list_done_hashes_calls
                .lock()
                .expect("list_done_hashes_calls lock")
                .push((tenant_id, policy_hash));
            Ok(self
                .records
                .values()
                .filter_map(|record| {
                    (record.key().tenant_id() == tenant_id
                        && record.key().policy_hash() == policy_hash
                        && record.status().is_terminal())
                    .then_some(record.key().ovid_hash())
                })
                .collect())
        }
    }

    #[derive(Clone, Debug)]
    struct FailingDoneLedger;

    impl DoneLedger for FailingDoneLedger {
        type Error = io::Error;
        type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, io::Error>;

        fn batch_get(
            &self,
            _tenant_id: TenantId,
            _policy_hash: PolicyHash,
            _ovid_hashes: &[OvidHash],
        ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
            Err(io::Error::other("injected batch_get failure"))
        }

        fn batch_upsert(
            &self,
            _records: &[DoneLedgerRecord],
        ) -> Result<Self::CommitHandle, Self::Error> {
            Ok(ReadyCommitHandle::ok(DoneLedgerCommitReceipt::new(0, 0, 0)))
        }
    }

    /// DoneLedger that delegates reads but always fails writes.
    #[derive(Clone, Debug)]
    struct FailingUpsertDoneLedger {
        inner: TrackingDoneLedger,
    }

    impl DoneLedger for FailingUpsertDoneLedger {
        type Error = io::Error;
        type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, io::Error>;

        fn batch_get(
            &self,
            tenant_id: TenantId,
            policy_hash: PolicyHash,
            ovid_hashes: &[OvidHash],
        ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
            self.inner.batch_get(tenant_id, policy_hash, ovid_hashes)
        }

        fn batch_upsert(
            &self,
            _records: &[DoneLedgerRecord],
        ) -> Result<Self::CommitHandle, Self::Error> {
            Err(io::Error::other("injected batch_upsert failure"))
        }
    }

    /// DoneLedger whose first `batch_get` returns a wrong-length result.
    /// Only compiled in release mode because its sole consumer is gated on
    /// `#[cfg(not(debug_assertions))]`.
    #[cfg(not(debug_assertions))]
    #[derive(Clone, Debug)]
    struct WrongLengthDoneLedger {
        inner: TrackingDoneLedger,
        call_count: Arc<Mutex<u64>>,
    }

    #[cfg(not(debug_assertions))]
    impl WrongLengthDoneLedger {
        fn new(inner: TrackingDoneLedger) -> Self {
            Self {
                inner,
                call_count: Arc::new(Mutex::new(0)),
            }
        }
    }

    #[cfg(not(debug_assertions))]
    impl DoneLedger for WrongLengthDoneLedger {
        type Error = io::Error;
        type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, io::Error>;

        fn batch_get(
            &self,
            tenant_id: TenantId,
            policy_hash: PolicyHash,
            ovid_hashes: &[OvidHash],
        ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
            let mut count = self.call_count.lock().expect("call_count lock");
            *count += 1;
            if *count == 1 {
                // First call (Bloom-positive subset): return wrong length to
                // trigger the decorator's fallback path.
                Ok(Vec::new())
            } else {
                // Fallback call with the full original slice.
                self.inner.batch_get(tenant_id, policy_hash, ovid_hashes)
            }
        }

        fn batch_upsert(
            &self,
            records: &[DoneLedgerRecord],
        ) -> Result<Self::CommitHandle, Self::Error> {
            self.inner.batch_upsert(records)
        }
    }

    /// DoneLedger whose `list_done_hashes` always fails.
    #[derive(Clone, Debug)]
    struct FailingListDoneLedger;

    impl DoneLedger for FailingListDoneLedger {
        type Error = io::Error;
        type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, io::Error>;

        fn batch_get(
            &self,
            _tenant_id: TenantId,
            _policy_hash: PolicyHash,
            _ovid_hashes: &[OvidHash],
        ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
            Ok(Vec::new())
        }

        fn batch_upsert(
            &self,
            _records: &[DoneLedgerRecord],
        ) -> Result<Self::CommitHandle, Self::Error> {
            Ok(ReadyCommitHandle::ok(DoneLedgerCommitReceipt::new(0, 0, 0)))
        }

        fn list_done_hashes(
            &self,
            _tenant_id: TenantId,
            _policy_hash: PolicyHash,
        ) -> Result<Vec<OvidHash>, Self::Error> {
            Err(io::Error::other("injected list_done_hashes failure"))
        }
    }

    /// DoneLedger that wraps [`TrackingDoneLedger`] with a configurable
    /// `count_done_hashes` override for testing the count pre-check path.
    #[derive(Clone, Debug)]
    struct CountingDoneLedger {
        inner: TrackingDoneLedger,
        /// `Some(Ok(n))` returns a count, `Some(Err(()))` injects a failure,
        /// `None` would delegate to default (not used here).
        count_value: Option<Result<usize, ()>>,
    }

    impl CountingDoneLedger {
        fn with_count(inner: TrackingDoneLedger, count: usize) -> Self {
            Self {
                inner,
                count_value: Some(Ok(count)),
            }
        }

        fn with_count_error(inner: TrackingDoneLedger) -> Self {
            Self {
                inner,
                count_value: Some(Err(())),
            }
        }
    }

    impl DoneLedger for CountingDoneLedger {
        type Error = io::Error;
        type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, io::Error>;

        fn batch_get(
            &self,
            tenant_id: TenantId,
            policy_hash: PolicyHash,
            ovid_hashes: &[OvidHash],
        ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
            self.inner.batch_get(tenant_id, policy_hash, ovid_hashes)
        }

        fn batch_upsert(
            &self,
            records: &[DoneLedgerRecord],
        ) -> Result<Self::CommitHandle, Self::Error> {
            self.inner.batch_upsert(records)
        }

        fn list_done_hashes(
            &self,
            tenant_id: TenantId,
            policy_hash: PolicyHash,
        ) -> Result<Vec<OvidHash>, Self::Error> {
            self.inner.list_done_hashes(tenant_id, policy_hash)
        }

        fn count_done_hashes(
            &self,
            _tenant_id: TenantId,
            _policy_hash: PolicyHash,
        ) -> Result<Option<usize>, Self::Error> {
            match self.count_value {
                Some(Ok(n)) => Ok(Some(n)),
                Some(Err(())) => Err(io::Error::other("injected count failure")),
                None => Ok(None),
            }
        }
    }

    #[test]
    fn from_ledger_enables_filter_above_threshold() {
        let tenant_id = tenant(131);
        let policy_hash = policy(132);
        let mut records = Vec::new();
        for seed in 0..DoneLedgerBloomFilter::MIN_THRESHOLD as u64 {
            records.push(scanned_record(tenant_id, policy_hash, ovid(seed)));
        }
        let inner = TrackingDoneLedger::with_records(records);

        let wrapped =
            BloomFilteredDoneLedger::from_ledger(inner.clone(), tenant_id, policy_hash, "test");

        assert!(wrapped.has_filter());
        assert!(wrapped.filter_memory_bytes().is_some());
        assert_eq!(
            inner.list_done_hashes_calls(),
            vec![(tenant_id, policy_hash)]
        );
    }

    #[test]
    fn from_ledger_passthrough_below_threshold() {
        let tenant_id = tenant(141);
        let policy_hash = policy(142);
        let inner =
            TrackingDoneLedger::with_records([scanned_record(tenant_id, policy_hash, ovid(143))]);

        let wrapped = BloomFilteredDoneLedger::from_ledger(inner, tenant_id, policy_hash, "test");

        assert!(!wrapped.has_filter());
    }

    #[test]
    fn from_ledger_passthrough_on_enumeration_error() {
        let wrapped = BloomFilteredDoneLedger::from_ledger(
            FailingListDoneLedger,
            tenant(151),
            policy(152),
            "test",
        );

        assert!(!wrapped.has_filter());
    }

    #[test]
    fn from_ledger_skips_enumeration_when_count_below_threshold() {
        let tenant_id = tenant(161);
        let policy_hash = policy(162);
        let inner = TrackingDoneLedger::empty();
        let counting = CountingDoneLedger::with_count(inner.clone(), 5);

        let wrapped =
            BloomFilteredDoneLedger::from_ledger(counting, tenant_id, policy_hash, "test");

        assert!(!wrapped.has_filter());
        assert!(
            inner.list_done_hashes_calls().is_empty(),
            "count pre-check should skip list_done_hashes for below-threshold counts"
        );
    }

    #[test]
    fn from_ledger_skips_enumeration_when_count_exceeds_cap() {
        let tenant_id = tenant(171);
        let policy_hash = policy(172);
        let inner = TrackingDoneLedger::empty();
        let counting = CountingDoneLedger::with_count(inner.clone(), 30_000_000);

        let wrapped =
            BloomFilteredDoneLedger::from_ledger(counting, tenant_id, policy_hash, "test");

        assert!(!wrapped.has_filter());
        assert!(
            inner.list_done_hashes_calls().is_empty(),
            "count pre-check should skip list_done_hashes for over-cap counts"
        );
    }

    #[test]
    fn from_ledger_enumerates_when_count_is_viable() {
        let tenant_id = tenant(181);
        let policy_hash = policy(182);
        let mut records = Vec::new();
        for seed in 0..DoneLedgerBloomFilter::MIN_THRESHOLD as u64 {
            records.push(scanned_record(tenant_id, policy_hash, ovid(seed)));
        }
        let inner = TrackingDoneLedger::with_records(records);
        let counting =
            CountingDoneLedger::with_count(inner.clone(), DoneLedgerBloomFilter::MIN_THRESHOLD);

        let wrapped =
            BloomFilteredDoneLedger::from_ledger(counting, tenant_id, policy_hash, "test");

        assert!(wrapped.has_filter());
        assert_eq!(
            inner.list_done_hashes_calls().len(),
            1,
            "viable count should proceed to list_done_hashes"
        );
    }

    #[test]
    fn from_ledger_falls_through_on_count_error() {
        let tenant_id = tenant(191);
        let policy_hash = policy(192);
        let inner =
            TrackingDoneLedger::with_records([scanned_record(tenant_id, policy_hash, ovid(193))]);
        let counting = CountingDoneLedger::with_count_error(inner.clone());

        let wrapped =
            BloomFilteredDoneLedger::from_ledger(counting, tenant_id, policy_hash, "test");

        // Count error is non-fatal: falls through to enumeration.
        assert!(!wrapped.has_filter());
        assert_eq!(
            inner.list_done_hashes_calls().len(),
            1,
            "count error should fall through to list_done_hashes"
        );
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
    fn is_viable_count_matches_new_decisions() {
        // Below threshold: not viable.
        assert!(!DoneLedgerBloomFilter::is_viable_count(
            DoneLedgerBloomFilter::MIN_THRESHOLD - 1
        ));
        // At threshold: viable.
        assert!(DoneLedgerBloomFilter::is_viable_count(
            DoneLedgerBloomFilter::MIN_THRESHOLD
        ));
        // Above cap: not viable.
        assert!(!DoneLedgerBloomFilter::is_viable_count(30_000_000));
    }

    #[test]
    fn raw_u64_hasher_write_panics() {
        use std::hash::Hasher as _;

        let mut h = RawU64Hasher::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            h.write(b"must panic");
        }));
        assert!(result.is_err(), "RawU64Hasher::write should panic");
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
        let actual: HashSet<_> = hashes.iter().copied().collect();
        let expected = HashSet::from([terminal_hash]);
        assert_eq!(actual, expected);

        let mut filter = DoneLedgerBloomFilter::new(DoneLedgerBloomFilter::MIN_THRESHOLD)
            .expect("threshold-sized filter should be constructed");
        for hash in &hashes {
            filter.insert(hash);
        }

        assert!(filter.maybe_contains(&terminal_hash));
        assert!(!filter.maybe_contains(&retryable_hash));
    }

    #[test]
    fn passthrough_mode_delegates_original_batch() {
        let tenant_id = tenant(11);
        let policy_hash = policy(12);
        let present = ovid(13);
        let missing = ovid(14);
        let inner =
            TrackingDoneLedger::with_records([scanned_record(tenant_id, policy_hash, present)]);
        let small_hashes = activated_hashes(&[]);
        let wrapped = BloomFilteredDoneLedger::from_hashes(
            inner.clone(),
            &small_hashes[..DoneLedgerBloomFilter::MIN_THRESHOLD - 1],
        );

        assert!(!wrapped.has_filter());

        let results = wrapped
            .batch_get(tenant_id, policy_hash, &[present, missing])
            .expect("passthrough batch_get should succeed");
        assert_eq!(
            results[0].as_ref().map(|record| record.key().ovid_hash()),
            Some(present)
        );
        assert!(results[1].is_none());
        assert_eq!(inner.batch_get_calls(), vec![vec![present, missing]]);
    }

    #[test]
    fn all_bloom_negative_skips_inner_entirely() {
        let tenant_id = tenant(21);
        let policy_hash = policy(22);
        let done_hashes = activated_hashes(&[ovid(23)]);
        let filter = built_filter(&done_hashes);
        let inner = TrackingDoneLedger::empty();
        let wrapped = BloomFilteredDoneLedger::from_hashes(inner.clone(), &done_hashes);
        let negative_a = first_negative_hash(&filter, 30_000_000);
        let negative_b = first_negative_hash(&filter, 30_000_100);

        let results = wrapped
            .batch_get(tenant_id, policy_hash, &[negative_a, negative_b])
            .expect("Bloom-negative batch_get should succeed");

        assert_eq!(results, vec![None, None]);
        assert!(inner.batch_get_calls().is_empty());
    }

    #[test]
    fn partial_bloom_positive_delegates_only_positives() {
        let tenant_id = tenant(31);
        let policy_hash = policy(32);
        let positive_a = ovid(33);
        let positive_b = ovid(34);
        let done_hashes = activated_hashes(&[positive_a, positive_b]);
        let filter = built_filter(&done_hashes);
        let negative = first_negative_hash(&filter, 40_000_000);
        let inner = TrackingDoneLedger::with_records([
            scanned_record(tenant_id, policy_hash, positive_a),
            retryable_record(tenant_id, policy_hash, positive_b),
        ]);
        let wrapped = BloomFilteredDoneLedger::from_hashes(inner.clone(), &done_hashes);

        let results = wrapped
            .batch_get(tenant_id, policy_hash, &[positive_a, negative, positive_b])
            .expect("mixed batch_get should succeed");

        assert_eq!(
            results[0].as_ref().map(|record| record.key().ovid_hash()),
            Some(positive_a)
        );
        assert!(results[1].is_none());
        assert_eq!(
            results[2].as_ref().map(|record| record.key().ovid_hash()),
            Some(positive_b)
        );
        assert_eq!(inner.batch_get_calls(), vec![vec![positive_a, positive_b]]);
    }

    #[test]
    fn all_bloom_positive_delegates_original_slice() {
        let tenant_id = tenant(41);
        let policy_hash = policy(42);
        let positive_a = ovid(43);
        let positive_b = ovid(44);
        let done_hashes = activated_hashes(&[positive_a, positive_b]);
        let inner = TrackingDoneLedger::with_records([
            scanned_record(tenant_id, policy_hash, positive_a),
            scanned_record(tenant_id, policy_hash, positive_b),
        ]);
        let wrapped = BloomFilteredDoneLedger::from_hashes(inner.clone(), &done_hashes);

        let results = wrapped
            .batch_get(tenant_id, policy_hash, &[positive_a, positive_b])
            .expect("all-positive batch_get should succeed");

        assert_eq!(
            results[0].as_ref().map(|record| record.key().ovid_hash()),
            Some(positive_a)
        );
        assert_eq!(
            results[1].as_ref().map(|record| record.key().ovid_hash()),
            Some(positive_b)
        );
        assert_eq!(inner.batch_get_calls(), vec![vec![positive_a, positive_b]]);
    }

    #[test]
    fn batch_upsert_delegates_and_invalidates_across_clones() {
        let ledger = InMemoryDoneLedger::new();
        let tenant_id = tenant(51);
        let policy_hash = policy(52);
        let existing = ovid(53);
        let seed_handle = ledger
            .batch_upsert(&[scanned_record(tenant_id, policy_hash, existing)])
            .expect("seed upsert should succeed");
        seed_handle.wait().expect("seed upsert should be durable");

        let done_hashes = activated_hashes(&[existing]);
        let filter = built_filter(&done_hashes);
        let new_hash = first_negative_hash(&filter, 50_000_000);
        let wrapped = BloomFilteredDoneLedger::from_hashes(ledger.clone(), &done_hashes);
        let reader = wrapped.clone();

        assert_eq!(
            reader
                .batch_get(tenant_id, policy_hash, &[new_hash])
                .expect("pre-write batch_get should succeed"),
            vec![None]
        );

        let handle = wrapped
            .batch_upsert(&[scanned_record(tenant_id, policy_hash, new_hash)])
            .expect("decorated batch_upsert should succeed");
        handle
            .wait()
            .expect("decorated batch_upsert should be durable");

        let results = reader
            .batch_get(tenant_id, policy_hash, &[new_hash])
            .expect("post-write batch_get should succeed");
        assert_eq!(
            results[0].as_ref().map(|record| record.key().ovid_hash()),
            Some(new_hash)
        );
    }

    #[test]
    fn batch_upsert_forwards_records_unchanged() {
        let tenant_id = tenant(61);
        let policy_hash = policy(62);
        let record = scanned_record(tenant_id, policy_hash, ovid(63));
        let inner = TrackingDoneLedger::empty();
        let wrapped = BloomFilteredDoneLedger::passthrough(inner.clone());

        let handle = wrapped
            .batch_upsert(std::slice::from_ref(&record))
            .expect("batch_upsert should delegate");
        handle.wait().expect("delegated handle should resolve");

        assert_eq!(inner.batch_upsert_calls(), vec![vec![record]]);
    }

    #[test]
    fn list_done_hashes_delegates_unchanged() {
        let tenant_id = tenant(71);
        let policy_hash = policy(72);
        let terminal = ovid(73);
        let retryable = ovid(74);
        let inner = TrackingDoneLedger::with_records([
            scanned_record(tenant_id, policy_hash, terminal),
            retryable_record(tenant_id, policy_hash, retryable),
        ]);
        let wrapped = BloomFilteredDoneLedger::passthrough(inner.clone());

        let hashes = wrapped
            .list_done_hashes(tenant_id, policy_hash)
            .expect("list_done_hashes should delegate");

        assert_eq!(HashSet::<_>::from_iter(hashes), HashSet::from([terminal]));
        assert_eq!(
            inner.list_done_hashes_calls(),
            vec![(tenant_id, policy_hash)]
        );
    }

    #[test]
    fn empty_batch_returns_empty_without_inner_call() {
        let tenant_id = tenant(81);
        let policy_hash = policy(82);
        let done_hashes = activated_hashes(&[ovid(83)]);
        let inner = TrackingDoneLedger::empty();
        let wrapped = BloomFilteredDoneLedger::from_hashes(inner.clone(), &done_hashes);

        let results = wrapped
            .batch_get(tenant_id, policy_hash, &[])
            .expect("empty batch_get should succeed");

        assert!(results.is_empty());
        assert!(inner.batch_get_calls().is_empty());
    }

    #[test]
    fn batch_get_propagates_inner_error() {
        let tenant_id = tenant(91);
        let policy_hash = policy(92);
        let positive = ovid(93);
        let done_hashes = activated_hashes(&[positive]);
        let wrapped = BloomFilteredDoneLedger::from_hashes(FailingDoneLedger, &done_hashes);

        let error = wrapped
            .batch_get(tenant_id, policy_hash, &[positive])
            .expect_err("Bloom-positive delegated failure should propagate");

        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn failed_batch_upsert_does_not_invalidate_prefilter() {
        let tenant_id = tenant(111);
        let policy_hash = policy(112);
        let positive = ovid(113);
        let done_hashes = activated_hashes(&[positive]);
        let filter = built_filter(&done_hashes);
        let negative = first_negative_hash(&filter, 60_000_000);

        let tracking = TrackingDoneLedger::empty();
        let inner = FailingUpsertDoneLedger {
            inner: tracking.clone(),
        };
        let wrapped = BloomFilteredDoneLedger::from_hashes(inner, &done_hashes);

        let record = scanned_record(tenant_id, policy_hash, positive);
        let error = wrapped
            .batch_upsert(std::slice::from_ref(&record))
            .expect_err("failing inner upsert should propagate");
        assert_eq!(error.kind(), io::ErrorKind::Other);

        // Bloom-negative key must still be filtered without reaching inner,
        // proving the invalidation bit was not set by the failed upsert.
        let results = wrapped
            .batch_get(tenant_id, policy_hash, &[negative])
            .expect("batch_get after failed upsert should succeed");
        assert_eq!(results, vec![None]);
        assert!(
            tracking.batch_get_calls().is_empty(),
            "Bloom-negative key should not reach inner after failed upsert"
        );
    }

    #[test]
    fn empty_batch_upsert_does_not_invalidate_prefilter() {
        let tenant_id = tenant(161);
        let policy_hash = policy(162);
        let done_hashes = activated_hashes(&[ovid(163)]);
        let filter = built_filter(&done_hashes);
        let negative = first_negative_hash(&filter, 80_000_000);
        let inner = TrackingDoneLedger::empty();
        let wrapped = BloomFilteredDoneLedger::from_hashes(inner.clone(), &done_hashes);

        // Empty batch_upsert should succeed without invalidating the filter.
        let handle = wrapped
            .batch_upsert(&[])
            .expect("empty batch_upsert should succeed");
        handle
            .wait()
            .expect("empty batch_upsert handle should resolve");

        // Bloom-negative key must still be filtered, proving filter is active.
        let results = wrapped
            .batch_get(tenant_id, policy_hash, &[negative])
            .expect("batch_get after empty upsert should succeed");
        assert_eq!(results, vec![None]);
        assert!(
            inner.batch_get_calls().is_empty(),
            "Bloom-negative key should not reach inner after empty batch_upsert"
        );
    }

    /// Exercises the release-mode safety net: when the inner `batch_get`
    /// returns a wrong-length Vec, the decorator falls back to delegating
    /// the full original slice and permanently disables prefiltering.
    /// Gated to release-only because the `debug_assert_eq!` in the
    /// production code fires first in debug builds.
    #[cfg(not(debug_assertions))]
    #[test]
    fn wrong_length_inner_falls_back_and_invalidates() {
        let tenant_id = tenant(121);
        let policy_hash = policy(122);
        let positive_a = ovid(123);
        let positive_b = ovid(124);
        let done_hashes = activated_hashes(&[positive_a, positive_b]);
        let filter = built_filter(&done_hashes);
        let negative = first_negative_hash(&filter, 70_000_000);

        let tracking = TrackingDoneLedger::with_records([
            scanned_record(tenant_id, policy_hash, positive_a),
            scanned_record(tenant_id, policy_hash, positive_b),
        ]);
        let inner = WrongLengthDoneLedger::new(tracking.clone());
        let wrapped = BloomFilteredDoneLedger::from_hashes(inner, &done_hashes);

        // First call: mixed query forces the partial-positive path. The
        // wrong-length result triggers fallback to full delegation.
        let results = wrapped
            .batch_get(tenant_id, policy_hash, &[positive_a, negative, positive_b])
            .expect("fallback batch_get should succeed");

        assert_eq!(results.len(), 3);
        assert_eq!(
            results[0].as_ref().map(|r| r.key().ovid_hash()),
            Some(positive_a)
        );
        assert!(results[1].is_none());
        assert_eq!(
            results[2].as_ref().map(|r| r.key().ovid_hash()),
            Some(positive_b)
        );

        // Second call: filter must be permanently disabled, so the inner
        // receives the full original slice directly (no Bloom partitioning).
        let calls_before = tracking.batch_get_calls().len();
        let _ = wrapped
            .batch_get(tenant_id, policy_hash, &[positive_a, negative, positive_b])
            .expect("post-invalidation batch_get should succeed");
        let calls_after = tracking.batch_get_calls();
        // The second outer batch_get should produce exactly one inner call
        // with the full unfiltered slice (not a filtered subset).
        assert_eq!(calls_after.len(), calls_before + 1);
        assert_eq!(
            calls_after.last().expect("at least one call"),
            &vec![positive_a, negative, positive_b],
            "post-mismatch batch_get should delegate full slice, proving filter was invalidated"
        );
    }

    #[test]
    fn decorator_passes_done_ledger_conformance_suite() {
        let wrapped =
            BloomFilteredDoneLedger::from_hashes(InMemoryDoneLedger::new(), &activated_hashes(&[]));

        let checks = run_done_ledger_conformance(&wrapped)
            .expect("decorated done-ledger should satisfy conformance");

        assert_eq!(checks, 5);
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

        #[test]
        fn decorator_matches_inner_results(
            positives in proptest::collection::vec(any::<[u8; 32]>(), 0..32),
            queries in proptest::collection::vec(any::<[u8; 32]>(), 0..64),
        ) {
            let tenant_id = tenant(101);
            let policy_hash = policy(102);
            let mut positive_hashes = Vec::new();
            let mut seen = HashSet::new();
            for bytes in positives {
                let hash = OvidHash::from_bytes(bytes);
                if seen.insert(hash) {
                    positive_hashes.push(hash);
                }
            }
            let done_hashes = activated_hashes(&positive_hashes);
            let inner = TrackingDoneLedger::with_records(
                positive_hashes
                    .iter()
                    .copied()
                    .map(|hash| scanned_record(tenant_id, policy_hash, hash))
            );
            let wrapped = BloomFilteredDoneLedger::from_hashes(inner.clone(), &done_hashes);
            let query_hashes: Vec<_> = queries.into_iter().map(OvidHash::from_bytes).collect();

            let direct = inner
                .batch_get(tenant_id, policy_hash, &query_hashes)
                .expect("direct batch_get should succeed");
            let decorated = wrapped
                .batch_get(tenant_id, policy_hash, &query_hashes)
                .expect("decorated batch_get should succeed");

            prop_assert_eq!(decorated, direct);
        }
    }
}
