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
//! | S7 | **SplitCoverage** | Split-parent's spawned children exist and reference the parent. |

use std::collections::{BTreeMap, HashMap};
use std::panic;

use crate::coordination::cursor::{CursorBoundsCheck, check_cursor_bounds};
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
    /// A split-parent's spawned children fail referential integrity:
    /// children do not exist or do not reference the expected parent.
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
    /// Reusable buffer for S1 mutual-exclusion check.
    /// Cleared at the start of each `check_all` call to avoid per-call allocation.
    active_holders: HashMap<ShardKey, Vec<WorkerId>>,
    /// Reusable buffer for S7 split-coverage missing-child accumulation.
    scratch_missing: Vec<ShardId>,
    /// Reusable buffer for S7 split-coverage wrong-parent accumulation.
    scratch_wrong_parent: Vec<ShardId>,
}

impl InvariantChecker {
    /// Create a fresh checker with no history.
    pub fn new() -> Self {
        Self {
            prev_epochs: BTreeMap::new(),
            prev_terminal: BTreeMap::new(),
            prev_cursors: BTreeMap::new(),
            active_holders: HashMap::new(),
            scratch_missing: Vec::new(),
            scratch_wrong_parent: Vec::new(),
        }
    }

    /// Run all invariant checks (S1–S7) against the current coordinator state.
    ///
    /// Performs a **single pass** over `coordinator.shards()`, checking S2–S7
    /// inline and accumulating S1 data for a post-pass duplicate check. This
    /// avoids 7 separate iterations and eliminates per-call `Cursor`
    /// allocations in S5.
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
        // Collect into a Vec so we can iterate AND do point lookups.
        let shards: Vec<_> = coordinator.shards().collect();

        // Reuse S1 buffer across calls to avoid per-call allocation.
        self.active_holders.clear();

        for &((tid, key), record) in &shards {
            if tid != tenant {
                continue;
            }

            let id = (record.run, record.shard);

            // --- S1 accumulate: collect active lease holders for post-pass check ---
            // Uses `>=` (not `>`) to be conservative: a lease at its exact deadline
            // is treated as active for mutual-exclusion checking, even though the
            // coordinator's `is_leased_at()` treats `now == deadline` as expired.
            if let Some(holder) = record.lease()
                && holder.deadline() >= now
            {
                self.active_holders
                    .entry(key)
                    .or_default()
                    .push(holder.owner());
            }

            // --- S2: fence monotonicity ---
            let current_epoch = record.fence_epoch;
            if let Some(&prev) = self.prev_epochs.get(&id)
                && current_epoch < prev
            {
                violations.push(InvariantViolation::FenceMonotonicity {
                    run: id.0,
                    shard: id.1,
                    prev,
                    current: current_epoch,
                });
            }
            self.prev_epochs.insert(id, current_epoch);

            // --- S3: terminal irreversibility ---
            let current_status = record.status;
            if let Some(&prev) = self.prev_terminal.get(&id)
                && prev.is_terminal()
                && current_status != prev
                // Parked→Active is a legitimate transition via `unpark_shard`.
                && !(prev == ShardStatus::Parked && current_status == ShardStatus::Active)
            {
                violations.push(InvariantViolation::TerminalIrreversibility {
                    run: id.0,
                    shard: id.1,
                    was: prev,
                    now: current_status,
                });
            }
            self.prev_terminal.insert(id, current_status);

            // --- S4: record invariants ---
            #[cfg(panic = "unwind")]
            {
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
            // Under panic=abort, catch_unwind cannot intercept panics.
            // Call assert_invariants() directly; a panic will abort the
            // process, which is the best we can do since the invariant
            // truly failed.
            #[cfg(not(panic = "unwind"))]
            {
                record.assert_invariants();
            }

            // --- S5: cursor monotonicity (Cursor-allocation-free) ---
            // Direct Option<&[u8]> comparison instead of constructing Cursor objects.
            let prev_key = self.prev_cursors.get(&id).and_then(|o| o.as_deref());
            let curr_key = record.cursor.last_key();
            let cursor_regressed = match (prev_key, curr_key) {
                (Some(_), None) => true,                         // ResetToNone
                (Some(prev), Some(curr)) if curr < prev => true, // Regression
                _ => false,                                      // Forward or no-op
            };
            if cursor_regressed {
                violations.push(InvariantViolation::CursorMonotonicity {
                    run: id.0,
                    shard: id.1,
                });
            }
            let new_key: Option<Box<[u8]>> = curr_key.map(Box::from);
            self.prev_cursors.insert(id, new_key);

            // --- S6: cursor bounds ---
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

            // --- S7: split coverage ---
            if record.status == ShardStatus::Split {
                if record.spawned.is_empty() {
                    violations.push(InvariantViolation::SplitCoverage {
                        run: record.run,
                        shard: record.shard,
                        detail: "Split shard has no spawned children".to_owned(),
                    });
                } else {
                    self.scratch_missing.clear();
                    self.scratch_wrong_parent.clear();
                    for &child_id in &record.spawned {
                        let child_key = ShardKey::new(record.run, child_id);
                        match coordinator.shard_lookup(&tenant, &child_key) {
                            Some(child_record) => {
                                if child_record.parent != Some(record.shard) {
                                    self.scratch_wrong_parent.push(child_id);
                                }
                            }
                            None => self.scratch_missing.push(child_id),
                        }
                    }
                    if !self.scratch_missing.is_empty() {
                        violations.push(InvariantViolation::SplitCoverage {
                            run: record.run,
                            shard: record.shard,
                            detail: format!("Missing child shards: {:?}", self.scratch_missing),
                        });
                    }
                    if !self.scratch_wrong_parent.is_empty() {
                        violations.push(InvariantViolation::SplitCoverage {
                            run: record.run,
                            shard: record.shard,
                            detail: format!(
                                "Children with incorrect parent reference: {:?}",
                                self.scratch_wrong_parent
                            ),
                        });
                    }
                }
            }
        }

        // --- S1 post-pass: check for mutual exclusion violations ---
        for (key, holders) in &self.active_holders {
            if holders.len() > 1 {
                violations.push(InvariantViolation::MutualExclusion {
                    key: *key,
                    workers: [holders[0], holders[1]],
                });
            }
        }

        violations
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
    use gossip_stdx::RingBuffer;

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
            RingBuffer::new(),
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
            RingBuffer::new(),
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
            RingBuffer::new(),
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
            RingBuffer::new(),
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
            RingBuffer::new(),
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
            RingBuffer::new(),
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
            RingBuffer::new(),
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
            RingBuffer::new(),
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
            RingBuffer::new(),
        ));

        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&coord, &[], TENANT, now);
        assert_eq!(v.len(), 1);
        assert!(matches!(
            &v[0],
            InvariantViolation::CursorOutOfBounds { .. }
        ));
    }

    /// Helper to create a derived `ShardId` (bit 63 set), matching the
    /// convention used by the split subsystem.
    fn derived_shard_id(base: u64) -> ShardId {
        ShardId::from_raw((1u64 << 63) | base)
    }

    /// S7: Checker detects a Split shard with no spawned children.
    #[test]
    fn detects_split_no_children() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Split with empty spawned vec — S7 violation.
        // Also triggers S4 (assert_invariants panics on empty spawned for Split),
        // so we filter for only SplitCoverage below.
        coord.seed_shard_unchecked(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Split,
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

        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&coord, &[], TENANT, now);
        let s7: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::SplitCoverage { .. }))
            .collect();
        assert_eq!(s7.len(), 1);
        assert!(
            matches!(s7[0], InvariantViolation::SplitCoverage { detail, .. }
                if detail.contains("no spawned children"))
        );
    }

    /// S7: Checker detects a Split shard whose spawned child does not exist.
    #[test]
    fn detects_split_missing_child() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Parent is Split, references derived child 99 that doesn't exist
        // in the coordinator.
        let missing_child = derived_shard_id(99);
        coord.seed_shard_unchecked(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
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
        ));

        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&coord, &[], TENANT, now);
        let s7: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::SplitCoverage { .. }))
            .collect();
        assert_eq!(s7.len(), 1);
        assert!(
            matches!(s7[0], InvariantViolation::SplitCoverage { detail, .. }
                if detail.contains("Missing child"))
        );
    }

    /// S7: Checker detects a spawned child with an incorrect parent reference.
    #[test]
    fn detects_split_wrong_parent_ref() {
        let run = RunId::from_raw(1);
        let parent_shard = ShardId::from_raw(1);
        let child_shard = derived_shard_id(2);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Parent shard 1 is Split, references derived child shard.
        coord.seed_shard_unchecked(ShardRecord::from_raw_parts(
            TENANT,
            run,
            parent_shard,
            ShardStatus::Split,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'z']),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![child_shard],
            RingBuffer::new(),
        ));

        // Child shard exists but points to wrong parent (derived 999 instead of 1).
        coord.seed_shard_unchecked(ShardRecord::from_raw_parts(
            TENANT,
            run,
            child_shard,
            ShardStatus::Active,
            None,
            ShardSpec::with_range(vec![b'a'], vec![b'm']),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            Some(ShardId::from_raw(999)),
            vec![],
            RingBuffer::new(),
        ));

        let mut checker = InvariantChecker::new();
        let v = checker.check_all(&coord, &[], TENANT, now);
        let s7: Vec<_> = v
            .iter()
            .filter(|v| matches!(v, InvariantViolation::SplitCoverage { .. }))
            .collect();
        assert_eq!(s7.len(), 1);
        assert!(
            matches!(s7[0], InvariantViolation::SplitCoverage { detail, .. }
                if detail.contains("incorrect parent"))
        );
    }

    /// S3: Parked→Active is a legitimate unpark transition, not an S3 violation.
    #[test]
    fn parked_to_active_not_flagged_as_terminal_reversion() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let spec = ShardSpec::with_range(vec![b'a'], vec![b'z']);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed as Parked (terminal per is_terminal()).
        coord.seed_shard(ShardRecord::from_raw_parts(
            TENANT,
            run,
            shard,
            ShardStatus::Parked,
            Some(crate::coordination::record::ParkReason::Other),
            spec.clone(),
            Cursor::initial(),
            CursorSemantics::Completed,
            None,
            FenceEpoch::INITIAL,
            None,
            vec![],
            RingBuffer::new(),
        ));
        let mut checker = InvariantChecker::new();
        assert!(checker.check_all(&coord, &[], TENANT, now).is_empty());

        // Re-seed as Active — simulates unpark_shard.
        // Bump fence epoch to match what unpark_shard does.
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
            FenceEpoch::INITIAL.increment(),
            None,
            vec![],
            RingBuffer::new(),
        ));

        let v = checker.check_all(&coord, &[], TENANT, now);
        assert!(
            v.is_empty(),
            "Parked→Active should not trigger S3 TerminalIrreversibility, got: {v:?}"
        );
    }
}
