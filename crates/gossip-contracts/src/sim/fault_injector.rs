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
//!   **followed by** synthetic records (via [`Iterator::chain`]).
//! - [`shard_lookup()`](FaultInjectingIntrospector::shard_lookup) delegates
//!   to the inner backend only — synthetic records are invisible to point
//!   lookups.
//!
//! This asymmetry models a class of real-world distributed-system bugs
//! where a full scan reveals inconsistencies that targeted reads miss
//! (e.g., stale replicas visible in range scans but masked by read-repair
//! on point lookups).
//!
//! # Scope
//!
//! This type is confined to dedicated checker tests — it is **not** used
//! inside the main `CoordinationSim::run` loop. Running it in the sim
//! would require distinguishing expected violations (injected) from
//! unexpected violations (real bugs), adding complexity for no safety gain.

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
    pub fn inject_shard(&mut self, tenant: TenantId, key: ShardKey, record: ShardRecord) {
        self.synthetic_records.push((tenant, key, record));
    }

    /// Access the underlying backend for assertions that injection did
    /// not modify coordinator state.
    pub fn inner(&self) -> &B {
        &self.inner
    }
}

/// Composes real and synthetic records into a unified observation stream.
///
/// Uses `Box<dyn Iterator>` for `ShardIter` because the concrete chain
/// type (`Chain<B::ShardIter<'_>, Map<...>>`) varies with `B` and cannot
/// be named without `impl Trait` in associated types (which GATs
/// intentionally avoid here for composability — see `backend.rs`).
impl<B: SimIntrospection> SimIntrospection for FaultInjectingIntrospector<B> {
    type ShardIter<'a>
        = Box<dyn Iterator<Item = ((TenantId, ShardKey), &'a ShardRecord)> + 'a>
    where
        Self: 'a;

    /// Yields all real records first, then all synthetic records.
    ///
    /// The ordering is load-bearing: the checker processes records
    /// sequentially, so placing synthetic records after real ones
    /// allows them to trigger monotonicity violations (S2, S3, S5)
    /// when they carry regressed values for the same `(RunId, ShardId)`.
    fn shards(&self) -> Self::ShardIter<'_> {
        let real = self.inner.shards();
        let synthetic = self
            .synthetic_records
            .iter()
            .map(|(tenant, key, record)| ((*tenant, *key), record));
        Box::new(real.chain(synthetic))
    }

    fn shard_count(&self) -> usize {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::cursor::Cursor;
    use crate::coordination::in_memory::InMemoryCoordinator;
    use crate::coordination::lease::LeaseHolder;
    use crate::coordination::record::{ShardRecord, ShardStatus};
    use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
    use crate::identity::{FenceEpoch, LogicalTime, RunId, ShardId, ShardKey, TenantId, WorkerId};
    use crate::sim::invariants::{InvariantChecker, InvariantViolation};
    use gossip_stdx::RingBuffer;

    const TENANT: TenantId = TenantId::from_bytes([0x01; 32]);
    const LEASE_DUR: u64 = 100;

    fn make_key(run: u64, shard: u64) -> ShardKey {
        ShardKey::new(RunId::from_raw(run), ShardId::from_raw(shard))
    }

    fn active_record_with_lease(run: u64, shard: u64, worker: u64, deadline: u64) -> ShardRecord {
        ShardRecord::from_raw_parts(
            TENANT,
            RunId::from_raw(run),
            ShardId::from_raw(shard),
            ShardStatus::Active,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::initial(),
            CursorSemantics::Completed,
            Some(LeaseHolder::new(
                WorkerId::from_raw(worker),
                LogicalTime::from_raw(deadline),
            )),
            FenceEpoch::INITIAL,
            None,
            vec![],
            RingBuffer::new(),
        )
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
        let real_record = active_record_with_lease(1, 1, 1, 200);
        coord.seed_shard(real_record);

        // Wrap in fault injector and add synthetic record:
        // worker 2 also "holds" a lease on the same shard key.
        let mut injector = FaultInjectingIntrospector::new(coord);
        let synthetic = active_record_with_lease(1, 1, 2, 200);
        injector.inject_shard(TENANT, key, synthetic);

        // Verify shard_count reflects both real and synthetic.
        assert_eq!(injector.shard_count(), 2);

        // Run checker — should detect S1 violation.
        let now = LogicalTime::from_raw(100);
        let mut checker = InvariantChecker::new();
        let violations = checker.check_all(&injector, &[], TENANT, now);

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

    /// Injector with no synthetic records passes through cleanly.
    #[test]
    fn no_injection_no_violations() {
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);
        let record = ShardRecord::new_active(
            TENANT,
            RunId::from_raw(1),
            ShardId::from_raw(1),
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            CursorSemantics::Completed,
        );
        coord.seed_shard(record);

        let injector = FaultInjectingIntrospector::new(coord);
        assert_eq!(injector.shard_count(), 1);

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();
        let violations = checker.check_all(&injector, &[], TENANT, now);
        assert!(violations.is_empty());
    }

    /// shard_lookup delegates to inner only — synthetic records invisible.
    #[test]
    fn shard_lookup_ignores_synthetic() {
        let coord = InMemoryCoordinator::new(LEASE_DUR);
        let mut injector = FaultInjectingIntrospector::new(coord);

        let key = make_key(1, 1);
        let synthetic = active_record_with_lease(1, 1, 2, 200);
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
        let record = ShardRecord::new_active(
            TENANT,
            RunId::from_raw(1),
            ShardId::from_raw(1),
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            CursorSemantics::Completed,
        );
        coord.seed_shard(record);

        let mut injector = FaultInjectingIntrospector::new(coord);
        let synthetic = active_record_with_lease(1, 1, 2, 200);
        injector.inject_shard(TENANT, make_key(1, 1), synthetic);

        // Inner coordinator still has exactly 1 shard.
        assert_eq!(injector.inner().shard_count(), 1);
    }

    /// S2: Checker detects fence epoch regression via injected record.
    #[test]
    fn detects_fence_regression_via_injection() {
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed with fence epoch 5.
        let key = make_key(1, 1);
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            RunId::from_raw(1),
            ShardId::from_raw(1),
            ShardStatus::Active,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::from_raw(5),
            None,
            vec![],
            RingBuffer::new(),
        ));

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();

        // First check establishes baseline.
        let v = checker.check_all(&coord, &[], TENANT, now);
        assert!(v.is_empty());

        // Now wrap in injector and replace the shard with lower epoch.
        // The real record still has epoch 5, but the injector adds
        // a synthetic with epoch 3. Since both iterate, the checker
        // sees the (run, shard) pair twice — first at epoch 5, then at 3.
        // The second observation regresses, triggering S2.
        let mut injector = FaultInjectingIntrospector::new(coord);
        let regressed = ShardRecord::from_raw_parts(
            TENANT,
            RunId::from_raw(1),
            ShardId::from_raw(1),
            ShardStatus::Active,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::from_raw(3),
            None,
            vec![],
            RingBuffer::new(),
        );
        injector.inject_shard(TENANT, key, regressed);

        let v = checker.check_all(&injector, &[], TENANT, now);
        let s2: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::FenceMonotonicity { .. }))
            .collect();
        assert!(
            !s2.is_empty(),
            "expected S2 fence regression violation, got: {:?}",
            v,
        );
    }

    /// S3: Checker detects terminal state reversion via injected record.
    ///
    /// First observation sees Done (terminal), second sees Active for the
    /// same (run, shard) — triggers TerminalIrreversibility.
    #[test]
    fn detects_terminal_reversion_via_injection() {
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed as Done (terminal).
        let key = make_key(1, 1);
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            RunId::from_raw(1),
            ShardId::from_raw(1),
            ShardStatus::Done,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            RingBuffer::new(),
        ));

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();

        // First check establishes Done baseline.
        let v = checker.check_all(&coord, &[], TENANT, now);
        assert!(v.is_empty());

        // Inject a synthetic Active record for the same shard.
        let mut injector = FaultInjectingIntrospector::new(coord);
        let reverted = ShardRecord::from_raw_parts(
            TENANT,
            RunId::from_raw(1),
            ShardId::from_raw(1),
            ShardStatus::Active,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            RingBuffer::new(),
        );
        injector.inject_shard(TENANT, key, reverted);

        let v = checker.check_all(&injector, &[], TENANT, now);
        let s3: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::TerminalIrreversibility { .. }))
            .collect();
        assert!(
            !s3.is_empty(),
            "expected S3 terminal reversion violation, got: {:?}",
            v,
        );
    }

    /// S5: Checker detects cursor regression via injected record.
    ///
    /// First observation sees cursor at 'h', second sees cursor regressed
    /// to 'c' for the same (run, shard) — triggers CursorMonotonicity.
    #[test]
    fn detects_cursor_regression_via_injection() {
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed with cursor at 'h'.
        let key = make_key(1, 1);
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            RunId::from_raw(1),
            ShardId::from_raw(1),
            ShardStatus::Active,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::with_last_key(vec![b'h']),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            RingBuffer::new(),
        ));

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();

        // First check establishes cursor at 'h'.
        let v = checker.check_all(&coord, &[], TENANT, now);
        assert!(v.is_empty());

        // Inject a synthetic record with cursor regressed to 'c'.
        let mut injector = FaultInjectingIntrospector::new(coord);
        let regressed = ShardRecord::from_raw_parts(
            TENANT,
            RunId::from_raw(1),
            ShardId::from_raw(1),
            ShardStatus::Active,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::with_last_key(vec![b'c']),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            RingBuffer::new(),
        );
        injector.inject_shard(TENANT, key, regressed);

        let v = checker.check_all(&injector, &[], TENANT, now);
        let s5: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::CursorMonotonicity { .. }))
            .collect();
        assert!(
            !s5.is_empty(),
            "expected S5 cursor regression violation, got: {:?}",
            v,
        );
    }

    /// S6: Checker detects cursor out-of-bounds via injected record.
    ///
    /// Injected record has cursor at '{' (ASCII 123), which is above the
    /// spec range [a=97, z=122).
    #[test]
    fn detects_cursor_out_of_bounds_via_injection() {
        let coord = InMemoryCoordinator::new(LEASE_DUR);

        let mut injector = FaultInjectingIntrospector::new(coord);
        let key = make_key(1, 1);
        let out_of_bounds = ShardRecord::from_raw_parts(
            TENANT,
            RunId::from_raw(1),
            ShardId::from_raw(1),
            ShardStatus::Active,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::with_last_key(vec![b'{']),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            RingBuffer::new(),
        );
        injector.inject_shard(TENANT, key, out_of_bounds);

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&injector, &[], TENANT, now);
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
        let coord = InMemoryCoordinator::new(LEASE_DUR);

        let mut injector = FaultInjectingIntrospector::new(coord);
        let key = make_key(1, 1);
        let missing_child = ShardId::from_raw((1u64 << 63) | 99);
        let split_record = ShardRecord::from_raw_parts(
            TENANT,
            RunId::from_raw(1),
            ShardId::from_raw(1),
            ShardStatus::Split,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![missing_child],
            RingBuffer::new(),
        );
        injector.inject_shard(TENANT, key, split_record);

        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&injector, &[], TENANT, now);

        // Filter for S7 violations specifically (S4 may also fire for
        // Split without proper parent field).
        let s7: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::SplitCoverage { .. }))
            .collect();
        assert!(
            !s7.is_empty(),
            "expected S7 split coverage violation for missing child, got: {:?}",
            v,
        );
    }
}
