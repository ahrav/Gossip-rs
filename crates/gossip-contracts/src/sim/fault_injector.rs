//! Observation-layer fault injection for invariant checker validation.
//!
//! [`FaultInjectingIntrospector`] wraps a real [`SimIntrospection`] backend
//! and injects synthetic shard records into the observation stream. This
//! enables testing the [`InvariantChecker`](super::invariants::InvariantChecker)
//! against states that the real backend cannot structurally produce.
//!
//! # Motivation
//!
//! `InMemoryCoordinator` stores shards in a
//! `HashMap<TenantId, HashMap<ShardKey, ShardRecord>>`, which structurally
//! prevents S1 (MutualExclusion) violations: at most one record exists per
//! key per tenant. The checker's S1 detection logic cannot be tested
//! against the real backend. `FaultInjectingIntrospector` creates synthetic
//! dual-holder scenarios at the observation layer, validating that the
//! checker *would* detect violations if they occurred.
//!
//! The same structural limitation applies to S2 (FenceMonotonicity),
//! S3 (TerminalIrreversibility), and S5 (CursorMonotonicity): the
//! in-memory backend enforces one-record-per-key, so it cannot represent
//! the conflicting observations needed to trigger these temporal
//! regression checks within a single `check_all` pass.
//!
//! # Design
//!
//! The injector operates at the **observation layer only**: it wraps
//! [`SimIntrospection`] (read-only iteration and lookups) without
//! implementing or affecting the mutation interface
//! ([`CoordinationBackend`](crate::coordination::traits::CoordinationBackend)).
//! This means injected records never participate in lease acquisition,
//! cursor advancement, or any other coordinator mutation.
//!
//! The key behavioral asymmetry is intentional:
//!
//! - [`shards()`](FaultInjectingIntrospector::shards) returns real records
//!   **followed by** synthetic records (via a two-phase iterator that yields
//!   real first, then synthetic, without allocating).
//! - [`shard_lookup()`](FaultInjectingIntrospector::shard_lookup) delegates
//!   to the inner backend only — synthetic records are invisible to point
//!   lookups.
//!
//! This asymmetry models a class of real-world distributed-system bugs
//! where a full scan reveals inconsistencies that targeted reads miss
//! (e.g., stale replicas visible in range scans but masked by read-repair
//! on point lookups).
//!
//! Synthetic records may be slab-backed when the inner backend pools bytes.
//! Cleanup runs through [`SimIntrospection::release_record_fields`] so this
//! wrapper does not need direct slab access.
//!
//! # Scope
//!
//! This type is confined to dedicated checker tests — it is **not** used
//! inside the main `CoordinationSim::run` loop. Running it in the sim
//! would require distinguishing expected violations (injected) from
//! unexpected violations (real bugs), adding complexity for no safety gain.
//!
//! Injection itself stores records in a `Vec`, so `inject_shard` may allocate
//! when the synthetic set grows. That is acceptable here because this helper
//! is test-only and configured before checker execution.

use crate::coordination::record::ShardRecord;
use crate::identity::{ShardKey, TenantId};
use crate::sim::backend::SimIntrospection;

/// Wraps a [`SimIntrospection`] backend and injects synthetic shard records
/// into the observation stream for checker validation.
///
/// Synthetic records are pre-configured before the test (not randomly
/// injected per step), so no PRNG state is consumed and determinism
/// is preserved.
///
/// Synthetic records live in a local `Vec` owned by this wrapper. Any growth
/// allocation happens at injection time, not while iterating with `shards()`.
///
/// # Iteration order contract
///
/// [`shards()`](Self::shards) yields real records first, then synthetic
/// records. This ordering matters for the stateful monotonicity checks in
/// [`InvariantChecker`](super::invariants::InvariantChecker): when the
/// checker sees the same `(RunId, ShardId)` twice in one pass, it
/// compares the second observation against the first. Placing synthetic
/// records after real ones lets tests inject "regressed" values (lower
/// fence epoch, earlier cursor, reverted status) that the checker detects
/// as violations of S2, S3, or S5.
pub struct FaultInjectingIntrospector<B: SimIntrospection> {
    inner: B,
    synthetic_records: Vec<(TenantId, ShardKey, ShardRecord)>,
}

impl<B: SimIntrospection> FaultInjectingIntrospector<B> {
    /// Create a fault-injecting wrapper around `inner` with no synthetic
    /// records. Use [`inject_shard`](Self::inject_shard) to add records
    /// before running the checker.
    pub fn new(inner: B) -> Self {
        Self {
            inner,
            synthetic_records: Vec::new(),
        }
    }

    /// Inject a synthetic shard record that will appear in `shards()` output.
    ///
    /// The record is observation-only — `shard_lookup()` still delegates
    /// to the inner backend, so injected records are not discoverable
    /// via point lookups. This matches real-world scenarios where an
    /// inconsistency is visible in a full scan but not in a targeted read.
    ///
    /// May grow the internal synthetic-record buffer.
    pub fn inject_shard(&mut self, tenant: TenantId, key: ShardKey, record: ShardRecord) {
        self.synthetic_records.push((tenant, key, record));
    }

    /// Access the underlying backend for assertions that injection did
    /// not modify coordinator state.
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Mutable access to the underlying backend (test helper).
    ///
    /// Allows allocating `ShardRecord` values from the inner coordinator's
    /// slab after the coordinator has been moved into the injector.
    #[cfg(test)]
    pub fn inner_mut(&mut self) -> &mut B {
        &mut self.inner
    }
}

/// Composes real and synthetic records into a unified observation stream.
///
/// `next()` walks the real iterator to completion before reading from the
/// synthetic slice iterator, preserving deterministic "real then synthetic"
/// ordering without constructing intermediate collections.
pub struct FaultInjectingShardIter<'a, I>
where
    I: Iterator<Item = ((TenantId, ShardKey), &'a ShardRecord)>,
{
    real: I,
    synthetic: core::slice::Iter<'a, (TenantId, ShardKey, ShardRecord)>,
}

impl<'a, I> Iterator for FaultInjectingShardIter<'a, I>
where
    I: Iterator<Item = ((TenantId, ShardKey), &'a ShardRecord)>,
{
    type Item = ((TenantId, ShardKey), &'a ShardRecord);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.real.next() {
            return Some(item);
        }
        self.synthetic
            .next()
            .map(|(tenant, key, record)| ((*tenant, *key), record))
    }
}

impl<B: SimIntrospection> SimIntrospection for FaultInjectingIntrospector<B> {
    type ShardIter<'a>
        = FaultInjectingShardIter<'a, B::ShardIter<'a>>
    where
        Self: 'a;

    type RunIter<'a>
        = <B as SimIntrospection>::RunIter<'a>
    where
        Self: 'a;

    type SpawnedIter<'a>
        = <B as SimIntrospection>::SpawnedIter<'a>
    where
        Self: 'a;

    /// Yields all real records first, then all synthetic records.
    ///
    /// The ordering is load-bearing: the checker processes records
    /// sequentially, so placing synthetic records after real ones
    /// allows them to trigger monotonicity violations (S2, S3, S5)
    /// when they carry regressed values for the same `(RunId, ShardId)`.
    fn shards(&self) -> Self::ShardIter<'_> {
        FaultInjectingShardIter {
            real: self.inner.shards(),
            synthetic: self.synthetic_records.iter(),
        }
    }

    /// Delegates to the inner backend — the fault injector only injects
    /// synthetic *shard* records, not runs.
    fn runs(&self) -> Self::RunIter<'_> {
        self.inner.runs()
    }

    fn shard_count(&self) -> usize {
        // Mirrors `shards()` output cardinality: all real records plus all
        // configured synthetic records.
        self.inner.shard_count() + self.synthetic_records.len()
    }

    fn shard_lookup(&self, tenant: &TenantId, key: &ShardKey) -> Option<&ShardRecord> {
        // Delegates to real backend only — synthetic records are
        // visible through full iteration but not point lookups.
        // This is intentional: S7 (SplitCoverage) uses shard_lookup
        // to verify child existence, so synthetic split-parents with
        // missing children correctly fail the lookup.
        self.inner.shard_lookup(tenant, key)
    }

    fn cursor_last_key<'a>(&'a self, record: &'a ShardRecord) -> Option<&'a [u8]> {
        self.inner.cursor_last_key(record)
    }

    fn spec_bounds<'a>(&'a self, record: &'a ShardRecord) -> (&'a [u8], &'a [u8]) {
        self.inner.spec_bounds(record)
    }

    fn validate_record_invariants(&self, record: &ShardRecord) -> Result<(), String> {
        self.inner.validate_record_invariants(record)
    }

    fn spawned_children<'a>(&'a self, record: &'a ShardRecord) -> Self::SpawnedIter<'a> {
        self.inner.spawned_children(record)
    }

    fn release_record_fields(&mut self, record: &mut ShardRecord) {
        self.inner.release_record_fields(record);
    }
}

/// Deallocate pooled fields from synthetic records before the inner
/// backend's slab is dropped.
///
/// Uses the trait-level cleanup hook rather than backend-specific slab APIs,
/// keeping fault injection compatible with any `SimIntrospection` backend.
/// The inner backend drops through its own `Drop` path after this cleanup.
impl<B: SimIntrospection> Drop for FaultInjectingIntrospector<B> {
    fn drop(&mut self) {
        for (_, _, record) in &mut self.synthetic_records {
            self.inner.release_record_fields(record);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::cursor::CursorUpdate;
    use crate::coordination::in_memory::InMemoryCoordinator;
    use crate::coordination::lease::LeaseHolder;
    use crate::coordination::record::{ShardRecord, ShardStatus};
    use crate::identity::{FenceEpoch, LogicalTime, RunId, ShardId, WorkerId};
    use crate::sim::invariants::{InvariantChecker, InvariantViolation};
    use crate::sim::test_util::{LEASE_DUR, TENANT, TestRecordBuilder, make_key};

    fn active_record_with_lease(
        run: u64,
        shard: u64,
        worker: u64,
        deadline: u64,
        slab: &mut gossip_stdx::ByteSlab,
    ) -> ShardRecord {
        TestRecordBuilder::new(TENANT, RunId::from_raw(run), ShardId::from_raw(shard))
            .lease(LeaseHolder::new(
                WorkerId::from_raw(worker),
                LogicalTime::from_raw(deadline),
            ))
            .build(slab)
    }

    /// S1: Checker detects mutual exclusion violation via injected duplicate.
    ///
    /// Worker A holds a real lease on shard 1. A synthetic record with
    /// Worker B holding a lease on the same shard key is injected. The
    /// checker should detect two active holders and report S1 violation.
    #[test]
    fn detects_mutual_exclusion_via_injection() {
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Real record: worker 1 holds lease on shard 1.
        let key = make_key(1, 1);
        let real_record = active_record_with_lease(1, 1, 1, 200, coord.slab_mut());
        coord.seed_shard(real_record);

        // Wrap in fault injector and add synthetic record:
        // worker 2 also "holds" a lease on the same shard key.
        let mut injector = FaultInjectingIntrospector::new(coord);
        let synthetic = active_record_with_lease(1, 1, 2, 200, injector.inner_mut().slab_mut());
        injector.inject_shard(TENANT, key, synthetic);

        // Verify shard_count reflects both real and synthetic.
        assert_eq!(injector.shard_count(), 2);

        // Run checker — should detect S1 violation.
        let now = LogicalTime::from_raw(100);
        let mut checker = InvariantChecker::new();
        let violations = checker.check_all(&injector, TENANT, now);

        let s1: Vec<_> = violations
            .iter()
            .filter(|v| matches!(v, InvariantViolation::MutualExclusion { .. }))
            .collect();
        assert_eq!(
            s1.len(),
            1,
            "expected exactly 1 S1 violation, got {}: {:?}",
            s1.len(),
            s1,
        );

        match &s1[0] {
            InvariantViolation::MutualExclusion { key: k, workers } => {
                assert_eq!(*k, key);
                let mut ids = [workers[0].as_raw(), workers[1].as_raw()];
                ids.sort();
                assert_eq!(ids, [1, 2]);
            }
            _ => unreachable!(),
        }
    }

    /// S1: No false positive when one lease holder has expired.
    ///
    /// Worker A has an active lease (deadline 200), Worker B has an expired
    /// lease (deadline 50). With `now = 100`, only Worker A is active, so
    /// the checker should NOT report a mutual-exclusion violation.
    #[test]
    fn s1_no_false_positive_for_expired_lease() {
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Real record: worker 1 holds lease expiring at 200.
        let key = make_key(1, 1);
        let real_record = active_record_with_lease(1, 1, 1, 200, coord.slab_mut());
        coord.seed_shard(real_record);

        // Inject synthetic: worker 2 had a lease that expired at 50.
        let mut injector = FaultInjectingIntrospector::new(coord);
        let expired = active_record_with_lease(1, 1, 2, 50, injector.inner_mut().slab_mut());
        injector.inject_shard(TENANT, key, expired);

        // now=100: worker 1 active (200 >= 100), worker 2 expired (50 < 100).
        let now = LogicalTime::from_raw(100);
        let mut checker = InvariantChecker::new();
        let violations = checker.check_all(&injector, TENANT, now);

        let s1: Vec<_> = violations
            .iter()
            .filter(|v| matches!(v, InvariantViolation::MutualExclusion { .. }))
            .collect();
        assert!(
            s1.is_empty(),
            "expected no S1 violation when one lease is expired, got: {:?}",
            s1,
        );
    }

    /// Injector with no synthetic records passes through cleanly.
    #[test]
    fn no_injection_no_violations() {
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);
        let record = TestRecordBuilder::new(TENANT, RunId::from_raw(1), ShardId::from_raw(1))
            .build(coord.slab_mut());
        coord.seed_shard(record);

        let injector = FaultInjectingIntrospector::new(coord);
        assert_eq!(injector.shard_count(), 1);

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();
        let violations = checker.check_all(&injector, TENANT, now);
        assert!(violations.is_empty());
    }

    /// shard_lookup delegates to inner only — synthetic records invisible.
    #[test]
    fn shard_lookup_ignores_synthetic() {
        let coord = InMemoryCoordinator::new(LEASE_DUR);
        let mut injector = FaultInjectingIntrospector::new(coord);

        let key = make_key(1, 1);
        let synthetic = active_record_with_lease(1, 1, 2, 200, injector.inner_mut().slab_mut());
        injector.inject_shard(TENANT, key, synthetic);

        // Point lookup should return None (only synthetic exists).
        assert!(injector.shard_lookup(&TENANT, &key).is_none());
        // But full iteration shows it.
        assert_eq!(injector.shard_count(), 1);
    }

    /// Injector never modifies underlying coordinator state.
    #[test]
    fn injection_does_not_modify_inner() {
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);
        let record = TestRecordBuilder::new(TENANT, RunId::from_raw(1), ShardId::from_raw(1))
            .build(coord.slab_mut());
        coord.seed_shard(record);

        let mut injector = FaultInjectingIntrospector::new(coord);
        let synthetic = active_record_with_lease(1, 1, 2, 200, injector.inner_mut().slab_mut());
        injector.inject_shard(TENANT, make_key(1, 1), synthetic);

        // Inner coordinator still has exactly 1 shard.
        assert_eq!(injector.inner().shard_count(), 1);
    }

    /// S2: Checker detects fence epoch regression via injected record.
    #[test]
    fn detects_fence_regression_via_injection() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed with fence epoch 5.
        let key = make_key(1, 1);
        let record = TestRecordBuilder::new(TENANT, run, shard)
            .fence_epoch(FenceEpoch::from_raw(5))
            .build(coord.slab_mut());
        coord.seed_shard(record);

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();

        // First check establishes baseline.
        let v = checker.check_all(&coord, TENANT, now);
        assert!(v.is_empty());

        // Now wrap in injector and replace the shard with lower epoch.
        // The real record still has epoch 5, but the injector adds
        // a synthetic with epoch 3. Since both iterate, the checker
        // sees the (run, shard) pair twice — first at epoch 5, then at 3.
        // The second observation regresses, triggering S2.
        let mut injector = FaultInjectingIntrospector::new(coord);
        let regressed = TestRecordBuilder::new(TENANT, run, shard)
            .fence_epoch(FenceEpoch::from_raw(3))
            .build(injector.inner_mut().slab_mut());
        injector.inject_shard(TENANT, key, regressed);

        let v = checker.check_all(&injector, TENANT, now);
        let s2: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::FenceMonotonicity { .. }))
            .collect();
        assert_eq!(
            s2.len(),
            1,
            "expected exactly 1 S2 fence regression violation, got: {:?}",
            v,
        );
    }

    /// S3: Checker detects terminal state reversion via injected record.
    ///
    /// First observation sees Done (terminal), second sees Active for the
    /// same (run, shard) — triggers TerminalIrreversibility.
    #[test]
    fn detects_terminal_reversion_via_injection() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed as Done (terminal).
        let key = make_key(1, 1);
        let record = TestRecordBuilder::new(TENANT, run, shard)
            .status(ShardStatus::Done)
            .build(coord.slab_mut());
        coord.seed_shard(record);

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();

        // First check establishes Done baseline.
        let v = checker.check_all(&coord, TENANT, now);
        assert!(v.is_empty());

        // Inject a synthetic Active record for the same shard.
        let mut injector = FaultInjectingIntrospector::new(coord);
        let reverted =
            TestRecordBuilder::new(TENANT, run, shard).build(injector.inner_mut().slab_mut());
        injector.inject_shard(TENANT, key, reverted);

        let v = checker.check_all(&injector, TENANT, now);
        let s3: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::TerminalIrreversibility { .. }))
            .collect();
        assert_eq!(
            s3.len(),
            1,
            "expected exactly 1 S3 terminal reversion violation, got: {:?}",
            v,
        );
    }

    /// S5: Checker detects cursor regression via injected record.
    ///
    /// First observation sees cursor at 'h', second sees cursor regressed
    /// to 'c' for the same (run, shard) — triggers CursorMonotonicity.
    #[test]
    fn detects_cursor_regression_via_injection() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed with cursor at 'h'.
        let key = make_key(1, 1);
        let record = TestRecordBuilder::new(TENANT, run, shard)
            .cursor(CursorUpdate::with_last_key(b"h"))
            .build(coord.slab_mut());
        coord.seed_shard(record);

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();

        // First check establishes cursor at 'h'.
        let v = checker.check_all(&coord, TENANT, now);
        assert!(v.is_empty());

        // Inject a synthetic record with cursor regressed to 'c'.
        let mut injector = FaultInjectingIntrospector::new(coord);
        let regressed = TestRecordBuilder::new(TENANT, run, shard)
            .cursor(CursorUpdate::with_last_key(b"c"))
            .build(injector.inner_mut().slab_mut());
        injector.inject_shard(TENANT, key, regressed);

        let v = checker.check_all(&injector, TENANT, now);
        let s5: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::CursorMonotonicity { .. }))
            .collect();
        assert_eq!(
            s5.len(),
            1,
            "expected exactly 1 S5 cursor regression violation, got: {:?}",
            v,
        );
    }

    /// S6: Checker detects cursor out-of-bounds via injected record.
    ///
    /// Injected record has cursor at '{' (ASCII 123), which is above the
    /// spec range [a=97, z=122).
    #[test]
    fn detects_cursor_out_of_bounds_via_injection() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let coord = InMemoryCoordinator::new(LEASE_DUR);

        let mut injector = FaultInjectingIntrospector::new(coord);
        let key = make_key(1, 1);
        let out_of_bounds = TestRecordBuilder::new(TENANT, run, shard)
            .cursor(CursorUpdate::with_last_key(b"{"))
            .build(injector.inner_mut().slab_mut());
        injector.inject_shard(TENANT, key, out_of_bounds);

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&injector, TENANT, now);
        let s6: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::CursorOutOfBounds { .. }))
            .collect();
        assert_eq!(
            s6.len(),
            1,
            "expected exactly 1 S6 cursor out-of-bounds violation, got: {:?}",
            v,
        );
    }

    /// S7: Checker detects missing split child via injected record.
    ///
    /// Injected Split-status shard references a child that doesn't exist
    /// in the coordinator — triggers SplitCoverage.
    #[test]
    fn detects_missing_split_child_via_injection() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let coord = InMemoryCoordinator::new(LEASE_DUR);

        let mut injector = FaultInjectingIntrospector::new(coord);
        let key = make_key(1, 1);
        let missing_child = ShardId::from_raw((1u64 << 63) | 99);
        let split_record = TestRecordBuilder::new(TENANT, run, shard)
            .status(ShardStatus::Split)
            .spawned([missing_child])
            .build(injector.inner_mut().slab_mut());
        injector.inject_shard(TENANT, key, split_record);

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&injector, TENANT, now);

        // Filter for S7 violations specifically (S4 may also fire for
        // Split without proper parent field).
        let s7: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::SplitCoverage { .. }))
            .collect();
        assert_eq!(
            s7.len(),
            1,
            "expected exactly 1 S7 split coverage violation for missing child, got: {:?}",
            v,
        );
    }
}
