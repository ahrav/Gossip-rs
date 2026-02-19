//! External invariant checker for the coordination protocol.
//!
//! This module verifies coordination invariants **from outside** the system
//! under test, following the FoundationDB simulation principle: never trust
//! the system's own validation for correctness verification. The coordinator
//! already runs `ShardRecord::assert_invariants()` after every mutation, but
//! those internal checks cannot detect cross-shard violations (S1 mutual
//! exclusion), temporal regressions that span multiple steps (S2 fence
//! monotonicity, S3 terminal irreversibility, S5 cursor monotonicity), or
//! referential integrity across parent/child records (S7 split coverage).
//! An external observer with its own accumulated history is required.
//!
//! # Architecture
//!
//! [`InvariantChecker`] is a stateful observer that maintains per-shard
//! history across calls. The simulation harness calls [`InvariantChecker::check_all`]
//! after **every** operation (successful or rejected), ensuring no operation
//! can leave the coordinator in a violating state without immediate detection.
//!
//! All checks derive solely from coordinator ground truth
//! ([`SimIntrospection`](super::backend::SimIntrospection)), never from
//! worker-side bookkeeping, to avoid false positives from stale worker views.
//!
//! # Checked invariants
//!
//! | Label | Name | Kind | Rule |
//! |-------|------|------|------|
//! | S1 | **MutualExclusion** | cross-shard | At most one worker holds a non-expired lease per shard. |
//! | S2 | **FenceMonotonicity** | temporal | `fence_epoch` never decreases for a given `(RunId, ShardId)`. |
//! | S3 | **TerminalIrreversibility** | temporal | Terminal states (`Done`, `Split`, `Parked`) never revert, except `Parked`->`Active` (unpark) which requires a fence bump. |
//! | S4 | **RecordInvariant** | structural | `ShardRecord::assert_invariants()` does not panic. |
//! | S5 | **CursorMonotonicity** | temporal | `cursor.last_key()` never decreases per shard. |
//! | S6 | **CursorBounds** | structural | Non-initial cursors remain within shard spec range. |
//! | S7 | **SplitCoverage** | referential | Split-parent's spawned children exist and reference the parent. |
//!
//! # Algorithm
//!
//! [`check_all`](InvariantChecker::check_all) performs a **single pass** over
//! all shard records from the coordinator. S2 through S7 are checked inline
//! during the pass. S1 requires a post-pass duplicate check because mutual
//! exclusion is a cross-record property: active lease holders are accumulated
//! into a `HashMap<ShardKey, Vec<WorkerId>>` during the pass, then scanned
//! for duplicates afterward.
//!
//! # Performance considerations
//!
//! - Scratch buffers (`active_holders`, `scratch_missing`, `scratch_wrong_parent`)
//!   are retained across calls and `.clear()`'d rather than reallocated,
//!   reducing per-call allocation pressure on the hot path. (The `shards`
//!   collection and per-shard cursor boxing still allocate each call.)
//! - S5 compares `Option<&[u8]>` directly rather than constructing `Cursor`
//!   objects, avoiding per-shard heap allocation for what is a simple
//!   lexicographic comparison.

use std::collections::{BTreeMap, HashMap};
use std::panic;

use crate::coordination::cursor::{CursorBoundsCheck, check_cursor_bounds};
use crate::coordination::record::ShardStatus;
use crate::identity::{FenceEpoch, LogicalTime, RunId, ShardId, ShardKey, TenantId, WorkerId};
use crate::sim::backend::SimIntrospection;

use super::worker::SimWorker;

// ---------------------------------------------------------------------------
// InvariantViolation
// ---------------------------------------------------------------------------

/// A detected invariant violation with enough context to diagnose the failure.
///
/// Each variant corresponds to one of the seven safety properties (S1-S7)
/// or a sub-property thereof. The harness collects all violations from a
/// simulation run into a `Vec<InvariantViolation>` for post-run analysis;
/// an empty vec means the run passed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum InvariantViolation {
    /// S1: Two workers hold non-expired leases on the same shard simultaneously.
    ///
    /// Only the first two conflicting workers are reported even if more exist,
    /// since the invariant is already violated with two.
    MutualExclusion {
        key: ShardKey,
        workers: [WorkerId; 2],
    },
    /// S2: A shard's fence epoch decreased between consecutive `check_all` calls.
    ///
    /// Fence epochs are monotonic counters that invalidate stale leases after
    /// re-acquisition. A decrease would allow a zombie worker to operate on a
    /// shard it no longer owns.
    FenceMonotonicity {
        run: RunId,
        shard: ShardId,
        prev: FenceEpoch,
        current: FenceEpoch,
    },
    /// S3: A terminal shard status (`Done`, `Split`, or `Parked`) reverted to
    /// a non-terminal state through a transition other than the allowed
    /// `Parked`->`Active` unpark path.
    TerminalIrreversibility {
        run: RunId,
        shard: ShardId,
        was: ShardStatus,
        now: ShardStatus,
    },
    /// S4: `ShardRecord::assert_invariants()` panicked, indicating a structural
    /// invariant violation in the record (e.g., `Parked` without `park_reason`,
    /// terminal shard with an active lease, fence epoch below `INITIAL`).
    RecordInvariant {
        run: RunId,
        shard: ShardId,
        message: String,
    },
    /// S5: Cursor `last_key` regressed -- either decreased lexicographically
    /// or was reset from `Some` to `None`. Cursor progress must be monotonic
    /// because it represents committed scan progress; regression would cause
    /// duplicate processing.
    CursorMonotonicity { run: RunId, shard: ShardId },
    /// S6: Cursor `last_key` is outside the shard's `[start, end)` spec range.
    /// A worker reporting progress outside its assigned key range indicates a
    /// routing or validation bug.
    CursorOutOfBounds { run: RunId, shard: ShardId },
    /// S7: A split-parent's spawned children fail referential integrity.
    ///
    /// Three sub-cases: (a) the split shard has an empty `spawned` list,
    /// (b) a referenced child shard does not exist in the coordinator,
    /// (c) a child shard's `parent` field does not reference this parent.
    SplitCoverage {
        run: RunId,
        shard: ShardId,
        detail: String,
    },
    /// S3 sub-property: `Parked`->`Active` transition (unpark) occurred without
    /// incrementing `fence_epoch`. The safety argument for allowing this
    /// otherwise-forbidden terminal reversion depends on the fence bump
    /// invalidating all pre-park leases. Without the bump, a worker that
    /// acquired during the parked state could operate with a stale fence.
    UnparkWithoutFenceBump {
        run: RunId,
        shard: ShardId,
        fence_at_park: FenceEpoch,
        fence_at_unpark: FenceEpoch,
    },
}

// ---------------------------------------------------------------------------
// InvariantChecker
// ---------------------------------------------------------------------------

/// Stateful external observer that tracks per-shard history across
/// simulation steps to detect temporal invariant violations.
///
/// The `prev_*` maps grow monotonically as new `(RunId, ShardId)` pairs
/// appear (e.g., from split operations that create child shards). They are
/// never pruned because temporal invariants (S2, S3, S5) must be checked
/// against the *entire* history of each shard's key, not just recent state.
///
/// Uses `BTreeMap<(RunId, ShardId), _>` for deterministic iteration order.
/// `ShardKey` intentionally omits `Ord` (it is an opaque identity, not an
/// ordered quantity), so the raw `(RunId, ShardId)` tuple serves as a
/// comparable surrogate.
pub struct InvariantChecker {
    /// Last-seen fence epoch per shard, for S2 monotonicity checks.
    prev_epochs: BTreeMap<(RunId, ShardId), FenceEpoch>,
    /// Last-seen shard status per shard, for S3 terminal irreversibility.
    prev_terminal: BTreeMap<(RunId, ShardId), ShardStatus>,
    /// Last-seen cursor `last_key` per shard, for S5 cursor monotonicity.
    /// `None` means the cursor was in its initial (no-key) state.
    prev_cursors: BTreeMap<(RunId, ShardId), Option<Box<[u8]>>>,
    /// Reusable buffer for S1 mutual-exclusion post-pass check.
    /// Cleared at the start of each `check_all` call; retained across calls
    /// so the backing allocation is reused in steady state.
    active_holders: HashMap<ShardKey, Vec<WorkerId>>,
    /// Reusable scratch buffer for S7 split-coverage: accumulates `ShardId`s
    /// of children referenced by a parent but missing from the coordinator.
    scratch_missing: Vec<ShardId>,
    /// Reusable scratch buffer for S7 split-coverage: accumulates `ShardId`s
    /// of children whose `parent` field does not match the expected parent.
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

    /// Run all invariant checks (S1-S7) against the current coordinator state.
    ///
    /// Performs a **single pass** over `coordinator.shards()`, checking S2-S7
    /// inline per record and accumulating S1 data for a post-pass duplicate
    /// check. This avoids 7 separate iterations and reuses scratch buffers
    /// across calls to reduce allocation pressure.
    ///
    /// # Returns
    ///
    /// An empty `Vec` when all invariants hold; otherwise one
    /// [`InvariantViolation`] per detected failure. Multiple violations can
    /// be reported from a single call (e.g., a corrupt coordinator state
    /// might violate both S4 and S3 simultaneously).
    ///
    /// # Parameters
    ///
    /// - `coordinator`: read-only view of the coordinator's shard records.
    /// - `_workers`: accepted for forward-compatibility (e.g., future checks
    ///   that compare worker-side bookkeeping against coordinator truth) but
    ///   not read by any current check. All current invariants derive solely
    ///   from coordinator state to avoid false positives from stale worker views.
    /// - `tenant`: only shards belonging to this tenant are checked; others
    ///   are skipped silently.
    /// - `now`: current logical time, used to determine whether leases are
    ///   active for S1.
    pub fn check_all(
        &mut self,
        coordinator: &impl SimIntrospection,
        _workers: &[&SimWorker],
        tenant: TenantId,
        now: LogicalTime,
    ) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();
        // Collect into a Vec so we can iterate AND do S7 point lookups
        // (child shard existence) within the same pass.
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
            let prev_epoch = self.prev_epochs.get(&id).copied();
            if let Some(prev) = prev_epoch
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
            let prev_status = self.prev_terminal.get(&id).copied();
            if let Some(prev) = prev_status
                && prev.is_terminal()
                && current_status != prev
            {
                if prev == ShardStatus::Parked && current_status == ShardStatus::Active {
                    // Parked→Active is a legitimate transition via `unpark_shard`,
                    // but it MUST bump the fence epoch to invalidate pre-park leases.
                    if let Some(old_epoch) = prev_epoch
                        && current_epoch <= old_epoch
                    {
                        violations.push(InvariantViolation::UnparkWithoutFenceBump {
                            run: id.0,
                            shard: id.1,
                            fence_at_park: old_epoch,
                            fence_at_unpark: current_epoch,
                        });
                    }
                } else {
                    violations.push(InvariantViolation::TerminalIrreversibility {
                        run: id.0,
                        shard: id.1,
                        was: prev,
                        now: current_status,
                    });
                }
            }
            self.prev_terminal.insert(id, current_status);

            // --- S4: record structural invariants ---
            // Delegates to the record's own self-check. Two code paths are
            // needed because `catch_unwind` is a no-op under `panic=abort`:
            //
            // - `panic=unwind` (default, test, Miri): catch the panic, extract
            //   the message, and report it as a non-fatal violation so the
            //   simulation can continue checking other shards.
            // - `panic=abort`: call directly. If the assertion fires, the
            //   process aborts -- there is no way to recover, but the panic
            //   message printed to stderr identifies the failing shard.
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
            #[cfg(not(panic = "unwind"))]
            {
                record.assert_invariants();
            }

            // --- S5: cursor monotonicity ---
            // Compares raw `Option<&[u8]>` slices rather than constructing
            // `Cursor` objects, avoiding a heap allocation per shard per step.
            let prev_key = self.prev_cursors.get(&id).and_then(|o| o.as_deref());
            let curr_key = record.cursor.last_key();
            let cursor_regressed = match (prev_key, curr_key) {
                (Some(_), None) => true,                         // reset to initial
                (Some(prev), Some(curr)) if curr < prev => true, // lexicographic regression
                _ => false,                                      // forward progress or unchanged
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

            // --- S7: split coverage (referential integrity) ---
            // For each Split-status shard, verify that every child ID in
            // `spawned` exists in the coordinator and points back to this parent.
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

        // --- S1 post-pass: mutual exclusion ---
        // S1 is a cross-record property (two records for the same ShardKey
        // with overlapping active leases), so it cannot be checked inline
        // per record. Instead, active holders were accumulated during the
        // pass and are now scanned for duplicates.
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

    /// Parked→Active without bumping fence_epoch triggers UnparkWithoutFenceBump.
    #[test]
    fn detects_unpark_without_fence_bump() {
        let run = RunId::from_raw(1);
        let shard = ShardId::from_raw(1);
        let spec = ShardSpec::with_range(vec![b'a'], vec![b'z']);
        let now = LogicalTime::from_raw(1);
        let mut coord = InMemoryCoordinator::new(LEASE_DUR);

        // Seed as Parked with fence epoch 3.
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
            FenceEpoch::from_raw(3),
            None,
            vec![],
            RingBuffer::new(),
        ));
        let mut checker = InvariantChecker::new();
        assert!(checker.check_all(&coord, &[], TENANT, now).is_empty());

        // Re-seed as Active with SAME fence epoch — missing fence bump.
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
            matches!(
                &v[0],
                InvariantViolation::UnparkWithoutFenceBump {
                    fence_at_park,
                    fence_at_unpark,
                    ..
                } if fence_at_park.as_raw() == 3 && fence_at_unpark.as_raw() == 3
            ),
            "expected UnparkWithoutFenceBump, got: {v:?}"
        );
    }
}
