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
//! | S1 | **MutualExclusion** | cross-shard | At most one worker holds a checker-active lease (`deadline >= now`) per shard. |
//! | S2 | **FenceMonotonicity** | temporal | `fence_epoch` never decreases for a given `(RunId, ShardId)`. |
//! | S3 | **TerminalIrreversibility** | temporal | Terminal states (`Done`, `Split`, `Parked`) never revert, except `Parked`->`Active` (unpark) which requires a fence bump. |
//! | S4 | **RecordInvariant** | structural | `ShardRecord::validate_invariants()` returns `Ok`. |
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
//! - Scratch buffers (`active_holders`, `scratch_missing`, `scratch_wrong_parent`,
//!   `scratch_prune`) are retained across calls and `.clear()`'d rather than
//!   reallocated, reducing per-call allocation pressure on the hot path.
//! - The main pass iterates `coordinator.shards()` directly rather than
//!   collecting into a `Vec`, since all coordinator borrows are shared (`&`)
//!   and coexist without conflict.
//! - S5 compares raw `Option<&[u8]>` slices and only updates `prev_cursors`
//!   when the value actually changed, avoiding a `Box<[u8]>` allocation on
//!   the common unchanged-cursor path.
//! - S6 consumes borrowed cursor/spec slices from `SimIntrospection`
//!   (`cursor_last_key` + `spec_bounds`) so bounds checks run without
//!   materializing `Cursor`/`ShardSpec` per record.
//! - After each pass, permanently terminal shards (`Done`, `Split`) are
//!   pruned from `prev_epochs` and `prev_cursors` to bound memory growth
//!   in long-running simulations with many split cascades. `prev_terminal`
//!   is retained so S3 can still detect illegal reversions.

use std::collections::{BTreeMap, HashMap};

use crate::coordination::record::{ShardRecord, ShardStatus};
use crate::identity::{FenceEpoch, LogicalTime, RunId, ShardId, ShardKey, TenantId, WorkerId};
use crate::sim::backend::SimIntrospection;

// ---------------------------------------------------------------------------
// SplitCoverageDetail
// ---------------------------------------------------------------------------

/// Sub-classification for S7 (SplitCoverage) violations, replacing
/// untyped string descriptions with pattern-matchable variants.
#[derive(Debug, Clone)]
pub enum SplitCoverageDetail {
    /// Split shard has an empty `spawned` list — no children were created.
    EmptySpawned,
    /// One or more child shard IDs referenced by the parent do not exist
    /// in the coordinator.
    MissingChildren { children: Vec<ShardId> },
    /// One or more child shards exist but their `parent` field does not
    /// reference this parent shard.
    WrongParent { children: Vec<ShardId> },
}

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
pub enum InvariantViolation {
    /// S1: Two workers hold checker-active leases (`deadline >= now`) on the
    /// same shard simultaneously.
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
    /// S4: `ShardRecord::validate_invariants()` detected a structural
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
    CursorMonotonicity {
        run: RunId,
        shard: ShardId,
        /// The previous cursor value (cloned at violation time for diagnostics).
        prev: Option<Box<[u8]>>,
        /// The current (regressed) cursor value.
        current: Option<Box<[u8]>>,
    },
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
        detail: SplitCoverageDetail,
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

/// Composite key for per-shard temporal history, scoped by tenant to prevent
/// cross-contamination when a single checker validates multiple tenants.
type HistoryKey = (TenantId, RunId, ShardId);

/// Stateful external observer that tracks per-shard history across
/// simulation steps to detect temporal invariant violations.
///
/// The `prev_*` maps grow as new `(RunId, ShardId)` pairs appear (e.g.,
/// from split operations that create child shards). After each `check_all`
/// pass, permanently terminal shards (`Done`, `Split`) have their
/// `prev_epochs` and `prev_cursors` entries pruned — no future operation
/// can change their fence or cursor. `prev_terminal` is retained so S3
/// can still detect illegal reversions. `Parked` shards are *not* pruned
/// because the `Parked`→`Active` unpark transition requires continued
/// monitoring.
///
/// Map keys include `TenantId` so a single checker instance can validate
/// multiple tenants without cross-contamination. Uses `BTreeMap` for
/// deterministic iteration order. `ShardKey` intentionally omits `Ord`
/// (it is an opaque identity, not an ordered quantity), so the raw
/// `(TenantId, RunId, ShardId)` tuple serves as a comparable surrogate.
pub struct InvariantChecker {
    /// Last-seen fence epoch per (tenant, run, shard), for S2 monotonicity.
    prev_epochs: BTreeMap<HistoryKey, FenceEpoch>,
    /// Last-seen shard status per (tenant, run, shard), for S3 terminal
    /// irreversibility.
    prev_terminal: BTreeMap<HistoryKey, ShardStatus>,
    /// Last-seen cursor `last_key` per (tenant, run, shard), for S5 cursor
    /// monotonicity. `None` means the cursor was in its initial state.
    prev_cursors: BTreeMap<HistoryKey, Option<Box<[u8]>>>,
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
    /// Reusable scratch buffer for post-pass pruning: accumulates keys of
    /// permanently terminal shards whose history entries can be discarded.
    scratch_prune: Vec<HistoryKey>,
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
            scratch_prune: Vec::new(),
        }
    }

    /// Run all invariant checks (S1-S7) against the current coordinator state.
    ///
    /// Performs a **single pass** over `coordinator.shards()`, delegating to
    /// per-invariant helpers (S1–S7) for each record, running a post-pass
    /// duplicate check for S1 (mutual exclusion), and pruning epoch/cursor
    /// history for permanently terminal shards (`Done`, `Split`). Scratch
    /// buffers are reused across calls to reduce allocation pressure.
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
    /// - `tenant`: only shards belonging to this tenant are checked; others
    ///   are skipped silently.
    /// - `now`: current logical time, used to determine whether leases are
    ///   active for S1.
    pub fn check_all(
        &mut self,
        coordinator: &impl SimIntrospection,
        tenant: TenantId,
        now: LogicalTime,
    ) -> Vec<InvariantViolation> {
        let mut violations = Vec::new();
        self.active_holders.clear();

        for ((tid, key), record) in coordinator.shards() {
            if tid != tenant {
                continue;
            }

            let id = (tenant, record.run, record.shard);

            self.accumulate_active_holder(key, record, now);
            let prev_epoch = self.check_fence_monotonicity(id, record.fence_epoch, &mut violations);
            self.check_terminal_irreversibility(
                id,
                record.status,
                prev_epoch,
                record.fence_epoch,
                &mut violations,
            );
            Self::check_record_invariant(record, &mut violations);
            let current_last_key = coordinator.cursor_last_key(record);
            let (spec_start, spec_end) = coordinator.spec_bounds(record);
            self.check_cursor_monotonicity(id, current_last_key, &mut violations);
            Self::check_cursor_in_bounds(
                record,
                current_last_key,
                spec_start,
                spec_end,
                &mut violations,
            );
            self.check_split_coverage(record, tenant, coordinator, &mut violations);
        }

        self.check_mutual_exclusion(&mut violations);

        // Prune permanently terminal shards (Done, Split) from epoch and
        // cursor history. These shards will never have new operations, so
        // their S2/S5 histories cannot change.  `prev_terminal` is *not*
        // pruned: S3 (terminal irreversibility) must retain the last-seen
        // status to detect illegal reversions if a coordinator bug reverts a
        // terminal shard.  Parked is excluded because unpark can revert it
        // to Active.
        self.scratch_prune.clear();
        for (&id, &status) in &self.prev_terminal {
            if matches!(status, ShardStatus::Done | ShardStatus::Split) {
                self.scratch_prune.push(id);
            }
        }
        for &id in &self.scratch_prune {
            self.prev_epochs.remove(&id);
            self.prev_cursors.remove(&id);
        }

        violations
    }

    /// S1 accumulate: collect active lease holders for post-pass check.
    ///
    /// Uses `>=` (not `>`) to be conservative: a lease at its exact deadline
    /// is treated as active for mutual-exclusion checking, even though the
    /// coordinator's `is_leased_at()` treats `now == deadline` as expired.
    ///
    /// This intentional off-by-one accepts false positives at boundary ticks
    /// over false negatives. A false positive (flagging a non-violation) is
    /// harmless — the simulation simply sees a spurious `MutualExclusion`
    /// that the coordinator would never actually produce. A false negative
    /// (missing a real dual-holder scenario because the checker discards a
    /// boundary-tick lease) would undermine the safety guarantee. Since
    /// `LogicalTime` advances in discrete ticks, the boundary-tick window
    /// is exactly one tick wide.
    fn accumulate_active_holder(&mut self, key: ShardKey, record: &ShardRecord, now: LogicalTime) {
        if let Some(holder) = record.lease()
            && holder.deadline() >= now
        {
            self.active_holders
                .entry(key)
                .or_default()
                .push(holder.owner());
        }
    }

    /// S2: fence monotonicity — returns the previous epoch for S3's use.
    ///
    /// Reads `prev_epochs` for the old value, inserts the current epoch,
    /// and returns the old value. The caller feeds this into
    /// [`check_terminal_irreversibility`](Self::check_terminal_irreversibility)
    /// for the Parked→Active fence-bump check.
    fn check_fence_monotonicity(
        &mut self,
        id: (TenantId, RunId, ShardId),
        current_epoch: FenceEpoch,
        violations: &mut Vec<InvariantViolation>,
    ) -> Option<FenceEpoch> {
        let prev_epoch = self.prev_epochs.get(&id).copied();
        if let Some(prev) = prev_epoch
            && current_epoch < prev
        {
            violations.push(InvariantViolation::FenceMonotonicity {
                run: id.1,
                shard: id.2,
                prev,
                current: current_epoch,
            });
        }
        self.prev_epochs.insert(id, current_epoch);
        prev_epoch
    }

    /// S3: terminal irreversibility.
    ///
    /// Terminal states (`Done`, `Split`, `Parked`) must never revert, except
    /// `Parked`→`Active` (unpark) which requires a fence bump. Receives the
    /// previous fence epoch from [`check_fence_monotonicity`](Self::check_fence_monotonicity)
    /// to validate the unpark fence-bump requirement.
    fn check_terminal_irreversibility(
        &mut self,
        id: (TenantId, RunId, ShardId),
        current_status: ShardStatus,
        prev_epoch: Option<FenceEpoch>,
        current_epoch: FenceEpoch,
        violations: &mut Vec<InvariantViolation>,
    ) {
        let prev_status = self.prev_terminal.get(&id).copied();
        if let Some(prev) = prev_status
            && prev.is_terminal()
            && current_status != prev
        {
            if prev == ShardStatus::Parked && current_status == ShardStatus::Active {
                // Use `==` (not `<=`): a fence *regression* (current < old) is
                // already caught by S2 (FenceMonotonicity). This check targets
                // only the "unpark without bump" case where the epoch stayed the
                // same. Using `<=` would double-report regressions as both S2
                // and UnparkWithoutFenceBump.
                if let Some(old_epoch) = prev_epoch
                    && current_epoch == old_epoch
                {
                    violations.push(InvariantViolation::UnparkWithoutFenceBump {
                        run: id.1,
                        shard: id.2,
                        fence_at_park: old_epoch,
                        fence_at_unpark: current_epoch,
                    });
                }
            } else {
                violations.push(InvariantViolation::TerminalIrreversibility {
                    run: id.1,
                    shard: id.2,
                    was: prev,
                    now: current_status,
                });
            }
        }
        self.prev_terminal.insert(id, current_status);
    }

    /// S4: record structural invariant.
    ///
    /// Delegates to the record's non-panicking [`validate_invariants`](ShardRecord::validate_invariants),
    /// which works correctly under both `panic=unwind` and `panic=abort`.
    fn check_record_invariant(record: &ShardRecord, violations: &mut Vec<InvariantViolation>) {
        if let Err(message) = record.validate_invariants() {
            violations.push(InvariantViolation::RecordInvariant {
                run: record.run,
                shard: record.shard,
                message,
            });
        }
    }

    /// S5: cursor monotonicity.
    ///
    /// Compares raw `Option<&[u8]>` slices rather than constructing `Cursor`
    /// objects, avoiding a heap allocation per shard per step.
    fn check_cursor_monotonicity(
        &mut self,
        id: (TenantId, RunId, ShardId),
        current_last_key: Option<&[u8]>,
        violations: &mut Vec<InvariantViolation>,
    ) {
        let prev_key = self.prev_cursors.get(&id).and_then(|o| o.as_deref());
        let cursor_regressed = match (prev_key, current_last_key) {
            (Some(_), None) => true,
            (Some(prev), Some(curr)) if curr < prev => true,
            _ => false,
        };
        if cursor_regressed {
            violations.push(InvariantViolation::CursorMonotonicity {
                run: id.1,
                shard: id.2,
                prev: prev_key.map(Box::from),
                current: current_last_key.map(Box::from),
            });
        }
        if prev_key != current_last_key {
            self.prev_cursors
                .insert(id, current_last_key.map(Box::from));
        }
    }

    /// S6: cursor bounds.
    ///
    /// Accepts borrowed slices from `SimIntrospection` accessors so the
    /// checker can validate bounds directly on slab-backed data without
    /// allocating temporary owned cursor/spec objects.
    fn check_cursor_in_bounds(
        record: &ShardRecord,
        current_last_key: Option<&[u8]>,
        spec_start: &[u8],
        spec_end: &[u8],
        violations: &mut Vec<InvariantViolation>,
    ) {
        if let Some(last_key) = current_last_key {
            let below_start = !spec_start.is_empty() && last_key < spec_start;
            let at_or_above_end = !spec_end.is_empty() && last_key >= spec_end;
            if below_start || at_or_above_end {
                violations.push(InvariantViolation::CursorOutOfBounds {
                    run: record.run,
                    shard: record.shard,
                });
            }
        }
    }

    /// S7: split coverage (referential integrity).
    ///
    /// For each Split-status shard, verifies that every child ID in `spawned`
    /// exists in the coordinator and points back to this parent.
    fn check_split_coverage(
        &mut self,
        record: &ShardRecord,
        tenant: TenantId,
        coordinator: &impl SimIntrospection,
        violations: &mut Vec<InvariantViolation>,
    ) {
        if record.status != ShardStatus::Split {
            return;
        }
        if record.spawned.is_empty() {
            violations.push(InvariantViolation::SplitCoverage {
                run: record.run,
                shard: record.shard,
                detail: SplitCoverageDetail::EmptySpawned,
            });
            return;
        }
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
                detail: SplitCoverageDetail::MissingChildren {
                    children: self.scratch_missing.clone(),
                },
            });
        }
        if !self.scratch_wrong_parent.is_empty() {
            violations.push(InvariantViolation::SplitCoverage {
                run: record.run,
                shard: record.shard,
                detail: SplitCoverageDetail::WrongParent {
                    children: self.scratch_wrong_parent.clone(),
                },
            });
        }
    }

    /// S1 post-pass: mutual exclusion.
    ///
    /// S1 is a cross-record property (two records for the same ShardKey with
    /// overlapping active leases), so it cannot be checked inline per record.
    /// Active holders were accumulated during the pass and are now scanned
    /// for duplicates.
    fn check_mutual_exclusion(&self, violations: &mut Vec<InvariantViolation>) {
        for (key, holders) in &self.active_holders {
            if holders.len() > 1 {
                violations.push(InvariantViolation::MutualExclusion {
                    key: *key,
                    workers: [holders[0], holders[1]],
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

#[cfg(test)]
#[path = "invariants_tests.rs"]
mod tests;
