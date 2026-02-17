//! External invariant checker for the coordination protocol.
//!
//! This module verifies coordination invariants **from outside** the system
//! under test, following the FoundationDB simulation principle: never trust
//! the system's own validation for correctness verification.
//!
//! # Checked invariants
//!
//! | Label | Name | Rule |
//! |-------|------|------|
//! | S1 | **MutualExclusion** | At most one worker holds a non-expired lease per shard. |
//! | S2 | **FenceMonotonicity** | `fence_epoch` never decreases for a given `(RunId, ShardId)`. |
//! | S3 | **TerminalIrreversibility** | Terminal states (`Done`, `Split`, `Parked`) never revert. |
//! | S4 | **RecordInvariant** | `ShardRecord::assert_invariants()` does not panic. |
//! | S5 | **CursorMonotonicity** | `cursor.last_key()` never decreases per shard (B2 extension). |
//! | S6 | **CursorBounds** | Non-initial cursors remain within shard spec range (B3 extension). |

use std::collections::{BTreeMap, HashMap};
use std::panic;

use crate::coordination::cursor::{
    CursorAdvance, CursorBoundsCheck, check_cursor_advance, check_cursor_bounds,
};
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::record::ShardStatus;
use crate::identity::{FenceEpoch, LogicalTime, RunId, ShardId, ShardKey, TenantId, WorkerId};

use super::worker::SimWorker;

// ---------------------------------------------------------------------------
// InvariantViolation
// ---------------------------------------------------------------------------

/// A detected invariant violation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum InvariantViolation {
    /// Two workers hold non-expired leases on the same shard simultaneously.
    MutualExclusion {
        key: ShardKey,
        workers: [WorkerId; 2],
    },
    /// A shard's fence epoch decreased.
    FenceMonotonicity {
        run: RunId,
        shard: ShardId,
        prev: FenceEpoch,
        current: FenceEpoch,
    },
    /// A terminal shard status changed to a different state.
    TerminalIrreversibility {
        run: RunId,
        shard: ShardId,
        was: ShardStatus,
        now: ShardStatus,
    },
    /// `ShardRecord::assert_invariants()` panicked.
    RecordInvariant {
        run: RunId,
        shard: ShardId,
        message: String,
    },
    /// Cursor `last_key` decreased or was reset to `None` for a shard.
    CursorMonotonicity { run: RunId, shard: ShardId },
    /// Cursor `last_key` is outside the shard spec range.
    CursorOutOfBounds { run: RunId, shard: ShardId },
    /// A split-parent's spawned children do not exist or their ranges
    /// do not collectively cover the parent's range.
    SplitCoverage {
        run: RunId,
        shard: ShardId,
        detail: String,
    },
}

// ---------------------------------------------------------------------------
// InvariantChecker
// ---------------------------------------------------------------------------

/// Stateful checker that tracks per-shard history to detect violations.
///
/// Uses `BTreeMap<(RunId, ShardId), _>` because `ShardKey` intentionally
/// has no `Ord`.
pub struct InvariantChecker {
    prev_epochs: BTreeMap<(RunId, ShardId), FenceEpoch>,
    prev_terminal: BTreeMap<(RunId, ShardId), ShardStatus>,
    prev_cursors: BTreeMap<(RunId, ShardId), Option<Box<[u8]>>>,
}

impl InvariantChecker {
    /// Create a fresh checker with no history.
    pub fn new() -> Self {
        Self {
            prev_epochs: BTreeMap::new(),
            prev_terminal: BTreeMap::new(),
            prev_cursors: BTreeMap::new(),
        }
    }

    /// Run all invariant checks (S1–S7) against the current coordinator state.
    ///
    /// Returns an empty `Vec` when all invariants hold.
    ///
    /// `_workers` is accepted for forward-compatibility (e.g., future checks
    /// that compare worker-side bookkeeping against coordinator truth) but is
    /// not read by any current check. All current invariants derive solely
    /// from coordinator state to avoid false positives from stale worker views.
    pub fn check_all(
        &mut self,
        coordinator: &InMemoryCoordinator,
        _workers: &[SimWorker],
        tenant: TenantId,
        now: LogicalTime,
    ) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();
        self.check_mutual_exclusion(coordinator, tenant, now, &mut violations);
        self.check_fence_monotonicity(coordinator, tenant, &mut violations);
        self.check_terminal_irreversibility(coordinator, tenant, &mut violations);
        self.check_record_invariants(coordinator, tenant, &mut violations);
        self.check_cursor_monotonicity(coordinator, tenant, &mut violations);
        self.check_cursor_bounds(coordinator, tenant, &mut violations);
        Self::check_split_coverage(coordinator, tenant, &mut violations);
        violations
    }

    /// S1: At most one worker holds a non-expired lease per shard at `now`.
    ///
    /// Derives ownership from coordinator state (not SimWorker bookkeeping)
    /// to avoid false positives from stale worker-side tracking.
    fn check_mutual_exclusion(
        &self,
        coordinator: &InMemoryCoordinator,
        tenant: TenantId,
        now: LogicalTime,
        violations: &mut Vec<InvariantViolation>,
    ) {
        // Group active (non-expired) lease holders by ShardKey.
        //
        // Uses `>=` (inclusive deadline) rather than the coordinator's strict
        // `<` in `is_leased_at`. The checker intentionally treats the deadline
        // tick as "still active" for a wider safety net: it can only produce
        // false positives (flagging a lease that the coordinator already
        // considers expired), never false negatives.
        let mut active_holders: HashMap<ShardKey, Vec<WorkerId>> = HashMap::new();

        for (&(tid, key), record) in coordinator.shards() {
            if tid != tenant {
                continue;
            }
            if let Some(holder) = record.lease()
                && holder.deadline() >= now
            {
                active_holders.entry(key).or_default().push(holder.owner());
            }
        }

        for (key, holders) in &active_holders {
            if holders.len() > 1 {
                violations.push(InvariantViolation::MutualExclusion {
                    key: *key,
                    workers: [holders[0], holders[1]],
                });
            }
        }
    }

    /// S2: `fence_epoch` is monotonically non-decreasing per shard.
    fn check_fence_monotonicity(
        &mut self,
        coordinator: &InMemoryCoordinator,
        tenant: TenantId,
        violations: &mut Vec<InvariantViolation>,
    ) {
        for (&(tid, _key), record) in coordinator.shards() {
            if tid != tenant {
                continue;
            }
            let id = (record.run, record.shard);
            let current = record.fence_epoch;
            if let Some(&prev) = self.prev_epochs.get(&id)
                && current < prev
            {
                violations.push(InvariantViolation::FenceMonotonicity {
                    run: id.0,
                    shard: id.1,
                    prev,
                    current,
                });
            }
            self.prev_epochs.insert(id, current);
        }
    }

    /// S3: Terminal states never revert.
    fn check_terminal_irreversibility(
        &mut self,
        coordinator: &InMemoryCoordinator,
        tenant: TenantId,
        violations: &mut Vec<InvariantViolation>,
    ) {
        for (&(tid, _key), record) in coordinator.shards() {
            if tid != tenant {
                continue;
            }
            let id = (record.run, record.shard);
            let current = record.status;
            if let Some(&prev) = self.prev_terminal.get(&id)
                && prev.is_terminal()
                && current != prev
            {
                violations.push(InvariantViolation::TerminalIrreversibility {
                    run: id.0,
                    shard: id.1,
                    was: prev,
                    now: current,
                });
            }
            self.prev_terminal.insert(id, current);
        }
    }

    /// S4: `ShardRecord::assert_invariants()` does not panic.
    ///
    /// Uses `catch_unwind` -- requires `panic = "unwind"` (default for test/dev).
    fn check_record_invariants(
        &self,
        coordinator: &InMemoryCoordinator,
        tenant: TenantId,
        violations: &mut Vec<InvariantViolation>,
    ) {
        for (&(tid, _key), record) in coordinator.shards() {
            if tid != tenant {
                continue;
            }
            let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                record.assert_invariants();
            }));
            if let Err(payload) = result {
                let message = if let Some(s) = payload.downcast_ref::<&str>() {
                    (*s).to_owned()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_owned()
                };
                violations.push(InvariantViolation::RecordInvariant {
                    run: record.run,
                    shard: record.shard,
                    message,
                });
            }
        }
    }

    /// S5 (B2): Cursor `last_key` is monotonically non-decreasing per shard.
    fn check_cursor_monotonicity(
        &mut self,
        coordinator: &InMemoryCoordinator,
        tenant: TenantId,
        violations: &mut Vec<InvariantViolation>,
    ) {
        for (&(tid, _key), record) in coordinator.shards() {
            if tid != tenant {
                continue;
            }
            let id = (record.run, record.shard);

            // Build a synthetic "previous" cursor for comparison.
            let prev_cursor = match self.prev_cursors.get(&id) {
                Some(Some(bytes)) => crate::coordination::Cursor::with_last_key(bytes.to_vec()),
                Some(None) | None => crate::coordination::Cursor::initial(),
            };

            let advance = check_cursor_advance(&prev_cursor, &record.cursor);
            if matches!(
                advance,
                CursorAdvance::Regression | CursorAdvance::ResetToNone
            ) {
                violations.push(InvariantViolation::CursorMonotonicity {
                    run: id.0,
                    shard: id.1,
                });
            }

            // Update history.
            let new_key: Option<Box<[u8]>> = record.cursor.last_key().map(Box::from);
            self.prev_cursors.insert(id, new_key);
        }
    }

    /// S6 (B3): Non-initial cursors are within shard spec bounds.
    fn check_cursor_bounds(
        &self,
        coordinator: &InMemoryCoordinator,
        tenant: TenantId,
        violations: &mut Vec<InvariantViolation>,
    ) {
        for (&(tid, _key), record) in coordinator.shards() {
            if tid != tenant {
                continue;
            }
            let bounds = check_cursor_bounds(&record.cursor, &record.spec);
            if matches!(
                bounds,
                CursorBoundsCheck::BelowRange | CursorBoundsCheck::AboveRange
            ) {
                violations.push(InvariantViolation::CursorOutOfBounds {
                    run: record.run,
                    shard: record.shard,
                });
            }
        }
    }

    /// S7: Split-parent's spawned children exist and their ranges cover
    /// the parent's range exactly (no gaps, no overlaps).
    ///
    /// Only checks shards in `Split` status. Children must:
    /// 1. All exist in the coordinator.
    /// 2. Be contiguous: child[i].end == child[i+1].start.
    /// 3. First child start == parent start.
    /// 4. Last child end == parent end.
    fn check_split_coverage(
        coordinator: &InMemoryCoordinator,
        tenant: TenantId,
        violations: &mut Vec<InvariantViolation>,
    ) {
        for (&(tid, _key), record) in coordinator.shards() {
            if tid != tenant || record.status != ShardStatus::Split {
                continue;
            }
            if record.spawned.is_empty() {
                violations.push(InvariantViolation::SplitCoverage {
                    run: record.run,
                    shard: record.shard,
                    detail: "Split shard has no spawned children".to_owned(),
                });
                continue;
            }

            // Collect child specs in spawned order.
            let mut child_specs = Vec::with_capacity(record.spawned.len());
            let mut missing = Vec::new();
            for &child_id in &record.spawned {
                let child_key = ShardKey::new(record.run, child_id);
                if let Some(child_record) = coordinator.shards().get(&(tenant, child_key)) {
                    child_specs.push(&child_record.spec);
                } else {
                    missing.push(child_id);
                }
            }

            if !missing.is_empty() {
                violations.push(InvariantViolation::SplitCoverage {
                    run: record.run,
                    shard: record.shard,
                    detail: format!("Missing child shards: {missing:?}"),
                });
                continue;
            }

            // Validate coverage using the same function the coordinator uses.
            if let Err(e) =
                crate::coordination::validate_split_coverage(&record.spec, &child_specs)
            {
                violations.push(InvariantViolation::SplitCoverage {
                    run: record.run,
                    shard: record.shard,
                    detail: format!("Split coverage validation failed: {e}"),
                });
            }
        }
    }
}

impl Default for InvariantChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::cursor::Cursor;
    use crate::coordination::in_memory::InMemoryCoordinator;
    use crate::coordination::record::ShardRecord;
    use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
    use crate::identity::{LogicalTime, RunId, ShardId, ShardKey, TenantId};

    const TENANT: TenantId = TenantId::from_bytes([0x01; 32]);
    const LEASE_DUR: u64 = 100;

    fn make_coordinator_with_shard(shard_raw: u64) -> InMemoryCoordinator {
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);
        let key = ShardKey::new(RunId::from_raw(1), ShardId::from_raw(shard_raw));
        let record = ShardRecord::new_active(
            TENANT,
            key.run(),
            key.shard(),
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            CursorSemantics::Completed,
        );
        coord.seed_shard(record);
        coord
    }

    // -- Smoke (happy-path documentation anchor) ----------------------------
    //
    // All other happy-path tests (mutual exclusion with single holder, fence
    // increase, terminal stability, cursor forward progress, cursor in-range)
    // are strictly subsumed by the simulation harness which runs check_all()
    // after every operation under 20+ seeds and multiple fault levels.

    #[test]
    fn smoke_no_violations_for_valid_state() {
        let coord = make_coordinator_with_shard(1);
        let now = LogicalTime::from_raw(1);
        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&coord, &[], TENANT, now);
        assert!(v.is_empty());
    }

    // -- Negative tests: verify the checker detects each violation ----------
    //
    // S1 (MutualExclusion) is not testable with the in-memory backend: the
    // HashMap<(TenantId, ShardKey), ShardRecord> enforces at most one record
    // per shard per tenant, making multiple active leases structurally
    // impossible. The check is defensive for future backends where concurrent
    // writes could produce duplicate lease holders.

    /// S2: Checker detects fence epoch regression.
    #[test]
    fn detects_fence_epoch_regression() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let spec = ShardSpec::with_range(vec![b'a'], vec![b'z']);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed with epoch 5.
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Active,
            None,
            spec.clone(),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::from_raw(5),
            None,
            vec![],
            vec![],
        ));
        let mut checker = InvariantChecker::new();
        assert!(checker.check_all(&coord, &[], TENANT, now).is_empty());

        // Re-seed with lower epoch — S2 violation.
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Active,
            None,
            spec,
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::from_raw(3),
            None,
            vec![],
            vec![],
        ));

        let v = checker.check_all(&coord, &[], TENANT, now);
        assert_eq!(v.len(), 1);
        assert!(
            matches!(&v[0], InvariantViolation::FenceMonotonicity { prev, current, .. }
                if prev.as_raw() == 5 && current.as_raw() == 3)
        );
    }

    /// S3: Checker detects terminal state reverting to non-terminal.
    #[test]
    fn detects_terminal_state_reversion() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let spec = ShardSpec::with_range(vec![b'a'], vec![b'z']);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed as Done (terminal).
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Done,
            None,
            spec.clone(),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        ));
        let mut checker = InvariantChecker::new();
        assert!(checker.check_all(&coord, &[], TENANT, now).is_empty());

        // Re-seed as Active — S3 violation (terminal reverted).
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Active,
            None,
            spec,
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        ));

        let v = checker.check_all(&coord, &[], TENANT, now);
        assert_eq!(v.len(), 1);
        assert!(
            matches!(&v[0], InvariantViolation::TerminalIrreversibility { was, now: cur, .. }
                if *was == ShardStatus::Done && *cur == ShardStatus::Active)
        );
    }

    /// S4: Checker detects a record that fails `assert_invariants()`.
    #[test]
    fn detects_record_invariant_violation() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Parked without park_reason — violates INV-1 in assert_invariants.
        coord.seed_shard_unchecked(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Parked,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        ));

        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&coord, &[], TENANT, now);
        assert_eq!(v.len(), 1);
        assert!(
            matches!(&v[0], InvariantViolation::RecordInvariant { message, .. }
                if message.contains("park_reason"))
        );
    }

    /// S5: Checker detects cursor regression (last_key decreased).
    #[test]
    fn detects_cursor_regression() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let spec = ShardSpec::with_range(vec![b'a'], vec![b'z']);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed with cursor at 'h'.
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Active,
            None,
            spec.clone(),
            Cursor::with_last_key(vec![b'h']),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        ));
        let mut checker = InvariantChecker::new();
        assert!(checker.check_all(&coord, &[], TENANT, now).is_empty());

        // Re-seed with cursor regressed to 'd' — S5 violation.
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Active,
            None,
            spec,
            Cursor::with_last_key(vec![b'd']),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        ));

        let v = checker.check_all(&coord, &[], TENANT, now);
        assert_eq!(v.len(), 1);
        assert!(matches!(
            &v[0],
            InvariantViolation::CursorMonotonicity { .. }
        ));
    }

    /// S6: Checker detects cursor above shard spec range.
    #[test]
    fn detects_cursor_above_range() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Cursor at '{' (ASCII 123) is above spec range [a=97, z=122).
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Active,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::with_last_key(vec![b'{']),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        ));

        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&coord, &[], TENANT, now);
        assert_eq!(v.len(), 1);
        assert!(matches!(
            &v[0],
            InvariantViolation::CursorOutOfBounds { .. }
        ));
    }

    /// S6: Checker detects cursor below shard spec range.
    #[test]
    fn detects_cursor_below_range() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Cursor at 0x01 is below spec range [a=97, z=122).
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Active,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::with_last_key(vec![0x01]),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            vec![],
        ));

        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&coord, &[], TENANT, now);
        assert_eq!(v.len(), 1);
        assert!(matches!(
            &v[0],
            InvariantViolation::CursorOutOfBounds { .. }
        ));
    }
}
