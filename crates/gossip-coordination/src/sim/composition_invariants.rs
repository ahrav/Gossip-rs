//! Cross-component invariant checker for the composition simulation.
//!
//! Validates properties that span the coordinator↔done-ledger boundary,
//! specifically the relationship between coordinator shard state and
//! done-ledger record provenance. Complements the per-component checkers:
//!
//! - **S1–S9** ([`InvariantChecker`]): coordination-internal invariants
//! - **I1–I10** ([`DoneLedgerInvariantChecker`]): persistence-internal invariants
//! - **C1–C4** (this module): cross-component provenance invariants
//!
//! # Invariants
//!
//! | ID | Property | Strategy |
//! |----|----------|----------|
//! | C1 | Provenance referential integrity | Sweep oracle committed records |
//! | C2 | Fence consistency | Sweep oracle committed records |
//! | C3 | No writes after terminal completion | Incremental write-log scan |
//! | C4 | Fence propagation (no stale fences) | Incremental write-log scan |
//!
//! C1 and C2 sweep all oracle committed records each step. The oracle
//! accumulates records over the simulation lifetime (OVID_POOL_SIZE bounds
//! OVID variety, not record count). C3 and C4 process only new
//! [`ProvenanceEntry`] values since the last `check_all` call.
//!
//! # Stale-lease writes and C4
//!
//! [`ScanLifecycleStaleLeaseWrite`] ops deliberately inject provenance with
//! a stale `fence_epoch` while the `lease_fence` reflects the real lease.
//! C4 will fire for every such committed entry — this is expected behavior,
//! not a false positive. Consumers that assert zero violations after a
//! stale-lease step must filter or expect `FencePropagationMismatch`.
//!
//! [`ScanLifecycleStaleLeaseWrite`]: super::composition::CompositionSimOp::ScanLifecycleStaleLeaseWrite
//!
//! # Scope
//!
//! C3/C4 observe only the scan-lifecycle provenance log (`ProvenanceEntry`
//! values appended by `exec_scan_lifecycle`, `exec_scan_crash_after_complete`,
//! and `exec_scan_stale_lease`). Completions via pass-through coordinator ops
//! (`Coord(SimOp::Complete)`) and `exec_session_lifecycle` terminal actions
//! do not log provenance entries; post-completion writes from those paths
//! are invisible to C3. Pass-through `Complete` never touches the
//! done-ledger, so C3 false negatives cannot arise there. The
//! `exec_session_lifecycle` gap requires threading provenance through
//! `WorkerSession` and is deferred to follow-up work.
//!
//! [`InvariantChecker`]: super::InvariantChecker
//! [`DoneLedgerInvariantChecker`]: gossip_persistence_inmemory::sim::DoneLedgerInvariantChecker

use std::collections::HashSet;
use std::fmt;

use gossip_contracts::identity::{FenceEpoch, RunId, ShardId, ShardKey, TenantId};
use gossip_contracts::persistence::DoneLedgerKey;
use gossip_persistence_inmemory::sim::DoneLedgerOracle;

use super::SimIntrospection;
use super::composition::ProvenanceEntry;

// ---------------------------------------------------------------------------
// CrossComponentViolation
// ---------------------------------------------------------------------------

/// Violation of a cross-component invariant (C1–C4).
///
/// Each variant carries enough diagnostic context to locate the root cause
/// without re-running the simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossComponentViolation {
    /// C1: done-ledger record references a `(run_id, shard_id)` the
    /// coordinator never created.
    ProvenanceOrphan {
        record_key: DoneLedgerKey,
        run_id: RunId,
        shard_id: ShardId,
    },

    /// C2: done-ledger record's `fence_epoch` exceeds the coordinator's
    /// current fence for that shard.
    FenceExceeded {
        record_key: DoneLedgerKey,
        provenance_fence: FenceEpoch,
        coordinator_fence: FenceEpoch,
    },

    /// C3: committed done-ledger write for a shard-epoch triple that the
    /// coordinator has already completed.
    WriteAfterTerminal {
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
    },

    /// C4: the fence epoch written into done-ledger provenance does not
    /// match the lease fence from `acquire_and_restore_into`.
    ///
    /// Expected for [`ScanLifecycleStaleLeaseWrite`] ops that deliberately
    /// inject stale provenance. See module-level docs for details.
    ///
    /// [`ScanLifecycleStaleLeaseWrite`]: super::composition::CompositionSimOp::ScanLifecycleStaleLeaseWrite
    FencePropagationMismatch {
        lease_fence: FenceEpoch,
        provenance_fence: FenceEpoch,
        shard_id: ShardId,
    },
}

impl fmt::Display for CrossComponentViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProvenanceOrphan {
                record_key,
                run_id,
                shard_id,
            } => write!(
                f,
                "C1 ProvenanceOrphan: record {record_key:?} references \
                 unknown shard (run={run_id:?}, shard={shard_id:?})"
            ),
            Self::FenceExceeded {
                record_key,
                provenance_fence,
                coordinator_fence,
            } => write!(
                f,
                "C2 FenceExceeded: record {record_key:?} has fence \
                 {provenance_fence:?} > coordinator fence {coordinator_fence:?}"
            ),
            Self::WriteAfterTerminal {
                run_id,
                shard_id,
                fence_epoch,
            } => write!(
                f,
                "C3 WriteAfterTerminal: committed write for completed \
                 triple (run={run_id:?}, shard={shard_id:?}, fence={fence_epoch:?})"
            ),
            Self::FencePropagationMismatch {
                lease_fence,
                provenance_fence,
                shard_id,
            } => write!(
                f,
                "C4 FencePropagationMismatch: shard {shard_id:?} lease \
                 fence {lease_fence:?} != provenance fence {provenance_fence:?}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// CompositionInvariantChecker
// ---------------------------------------------------------------------------

/// Stateful observer verifying cross-component invariants C1–C4.
///
/// Maintains history across simulation steps:
/// - `completed_shards`: tracks `(run_id, shard_id, fence_epoch)` triples
///   whose coordinator `complete()` succeeded, for C3 detection.
/// - `last_write_log_len`: index into the write log so C3/C4 only process
///   new entries each step.
///
/// # Usage
///
/// Call [`check_all`](Self::check_all) after every composition step, passing
/// the coordinator (for C1/C2 shard lookups), oracle (for C1/C2 committed
/// record iteration), and full write log (for C3/C4 incremental processing).
pub struct CompositionInvariantChecker {
    /// `(run_id, shard_id, lease_fence)` triples whose coordinator
    /// `complete()` succeeded. Uses the real lease fence (not the provenance
    /// fence) because the coordinator completes with the actual lease epoch.
    ///
    /// Grows monotonically (no pruning). Bounded by the total number of
    /// distinct shard completions across the simulation, which equals the
    /// initial shard count plus any splits — typically low hundreds.
    completed_shards: HashSet<(RunId, ShardId, FenceEpoch)>,

    /// Number of write-log entries processed so far. Entries before this
    /// index are skipped by C3/C4 on subsequent calls.
    last_write_log_len: usize,
}

impl CompositionInvariantChecker {
    /// Create a checker with no history.
    pub fn new() -> Self {
        Self {
            completed_shards: HashSet::new(),
            last_write_log_len: 0,
        }
    }

    /// Run all cross-component invariant checks (C1–C4).
    ///
    /// Returns an empty `Vec` when all invariants hold.
    ///
    /// # Parameters
    ///
    /// - `coordinator`: read-only view of coordinator shard state.
    /// - `oracle`: done-ledger model oracle with committed records.
    /// - `write_log`: full provenance log from the composition harness.
    /// - `tenant`: tenant scope for coordinator lookups.
    pub fn check_all(
        &mut self,
        coordinator: &impl SimIntrospection,
        oracle: &DoneLedgerOracle,
        write_log: &[ProvenanceEntry],
        tenant: TenantId,
    ) -> Vec<CrossComponentViolation> {
        let mut violations = Vec::new();

        // Phase 1: incremental write-log checks (C3, C4).
        self.check_write_log(write_log, &mut violations);

        // Phase 2: sweep oracle committed records (C1, C2).
        Self::check_committed_records(coordinator, oracle, tenant, &mut violations);

        violations
    }

    /// C3 + C4: process new write-log entries since the last call.
    ///
    /// For each new entry:
    /// 1. **C3 (check first):** if the entry committed records, verify its
    ///    provenance triple is not already in the completed set.
    /// 2. **C4:** if the entry committed records, verify the lease fence
    ///    matches the provenance fence.
    /// 3. **Update state:** if the coordinator completed the shard, record
    ///    the triple for future C3 checks.
    ///
    /// The check-then-update ordering for C3 ensures that the lifecycle
    /// that both writes and completes a shard is not falsely flagged —
    /// only subsequent writes for the same triple trigger a violation.
    fn check_write_log(
        &mut self,
        write_log: &[ProvenanceEntry],
        violations: &mut Vec<CrossComponentViolation>,
    ) {
        debug_assert!(
            write_log.len() >= self.last_write_log_len,
            "write_log must be append-only; got len {} but expected >= {}",
            write_log.len(),
            self.last_write_log_len,
        );

        for entry in write_log.iter().skip(self.last_write_log_len) {
            // C3: detect committed writes for already-completed shard-epoch triples.
            // Uses lease_fence (not fence_epoch) because the coordinator completes
            // with the actual lease epoch — the completion key must match.
            if entry.committed {
                let triple = (entry.run_id, entry.shard_id, entry.lease_fence);
                if self.completed_shards.contains(&triple) {
                    violations.push(CrossComponentViolation::WriteAfterTerminal {
                        run_id: entry.run_id,
                        shard_id: entry.shard_id,
                        fence_epoch: entry.lease_fence,
                    });
                }
            }

            // C4: detect fence propagation mismatch (lease fence ≠ provenance fence).
            if entry.committed && entry.lease_fence != entry.fence_epoch {
                violations.push(CrossComponentViolation::FencePropagationMismatch {
                    lease_fence: entry.lease_fence,
                    provenance_fence: entry.fence_epoch,
                    shard_id: entry.shard_id,
                });
            }

            // Update completed-shards set for future C3 checks.
            // Uses lease_fence (real fence) because the coordinator completes
            // with the actual lease epoch.
            if entry.coordinator_completed {
                self.completed_shards
                    .insert((entry.run_id, entry.shard_id, entry.lease_fence));
            }
        }
        self.last_write_log_len = write_log.len();
    }

    /// C1 + C2: sweep all oracle committed records against coordinator state.
    ///
    /// For each committed record:
    /// - **C1:** the provenance `(run_id, shard_id)` must exist in the
    ///   coordinator. `InMemoryCoordinator` never removes shard records
    ///   (terminal shards remain in the map), so a `None` lookup is
    ///   conclusive evidence of an orphaned provenance reference.
    /// - **C2:** the provenance `fence_epoch` must not exceed the
    ///   coordinator's current fence for that shard.
    fn check_committed_records(
        coordinator: &impl SimIntrospection,
        oracle: &DoneLedgerOracle,
        tenant: TenantId,
        violations: &mut Vec<CrossComponentViolation>,
    ) {
        for (key, record) in oracle.committed_iter() {
            let provenance = record.provenance();
            let shard_key = ShardKey::new(provenance.run_id(), provenance.shard_id());

            match coordinator.shard_lookup(&tenant, &shard_key) {
                None => {
                    // C1: provenance references a shard the coordinator
                    // never created.
                    violations.push(CrossComponentViolation::ProvenanceOrphan {
                        record_key: *key,
                        run_id: provenance.run_id(),
                        shard_id: provenance.shard_id(),
                    });
                }
                Some(shard_record) => {
                    // C2: provenance fence must not exceed coordinator's
                    // current fence.
                    if provenance.fence_epoch() > shard_record.fence_epoch {
                        violations.push(CrossComponentViolation::FenceExceeded {
                            record_key: *key,
                            provenance_fence: provenance.fence_epoch(),
                            coordinator_fence: shard_record.fence_epoch,
                        });
                    }
                }
            }
        }
    }
}

impl Default for CompositionInvariantChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "composition_invariants_tests.rs"]
mod tests;
