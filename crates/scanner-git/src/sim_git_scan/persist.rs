//! Deterministic persistence store for Git simulation.
//!
//! This store logs operations in deterministic order and supports
//! fault injection keyed by the logical `Persist` resource. It is
//! intended for simulation only and is not thread-safe.
//!
//! # Fault model
//! - Each `commit_finalize` call consumes one fault-plan read for `Persist`.
//! - I/O faults are surfaced as `PersistError::io`.
//! - Corruption faults are surfaced as backend errors.
//! - Faults abort the commit; no ops are logged.

use std::cell::RefCell;
use std::io;

use crate::{
    FinalizeOutcome, FinalizeOutput, OidBytes, PersistError, PersistenceStore, SeenBitmapPersister,
    SpillError,
};

use super::fault::{GitFaultInjector, GitFaultPlan, GitIoFault, GitResourceId};

/// Persistence operation phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistPhase {
    Data,
    Watermark,
    /// Incremental seen-bitmap delta during spill flushing.
    SeenDelta,
}

/// Logged persistence operation for simulation inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimPersistOp {
    pub phase: PersistPhase,
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// In-memory persistence store with deterministic fault injection.
///
/// # Invariants
/// - Commits are atomic: if a fault is injected, no ops are logged.
/// - On `FinalizeOutcome::Complete`, data ops are logged before watermark ops.
/// - On partial outcomes, watermark ops are ignored.
#[derive(Debug)]
pub struct SimPersistStore {
    log: RefCell<Vec<SimPersistOp>>,
    faults: RefCell<GitFaultInjector>,
}

impl SimPersistStore {
    /// Create a new persistence store with the given fault plan.
    pub fn new(plan: GitFaultPlan) -> Self {
        Self {
            log: RefCell::new(Vec::new()),
            faults: RefCell::new(GitFaultInjector::new(plan)),
        }
    }

    /// Returns the logged operations in write order.
    #[must_use]
    pub fn log(&self) -> Vec<SimPersistOp> {
        self.log.borrow().clone()
    }

    /// Clears the log (useful for multi-phase tests).
    pub fn clear(&self) {
        self.log.borrow_mut().clear();
    }

    fn apply_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        let (fault, _idx) = self.faults.borrow_mut().next_read(&GitResourceId::Persist);
        if let Some(io_fault) = &fault.fault {
            return Err(fault_to_error(io_fault));
        }
        if fault.corruption.is_some() {
            return Err(PersistError::backend("simulated persistence corruption"));
        }

        let mut log = self.log.borrow_mut();
        for op in &output.data_ops {
            log.push(SimPersistOp {
                phase: PersistPhase::Data,
                key: op.key.clone(),
                value: op.value.clone(),
            });
        }
        if matches!(output.outcome, FinalizeOutcome::Complete) {
            for op in &output.watermark_ops {
                log.push(SimPersistOp {
                    phase: PersistPhase::Watermark,
                    key: op.key.clone(),
                    value: op.value.clone(),
                });
            }
        }
        Ok(())
    }
}

impl Default for SimPersistStore {
    fn default() -> Self {
        Self::new(GitFaultPlan::default())
    }
}

impl SeenBitmapPersister for SimPersistStore {
    fn persist_seen_delta(&self, oids: &[OidBytes]) -> Result<(), SpillError> {
        let (fault, _idx) = self
            .faults
            .borrow_mut()
            .next_read(&GitResourceId::SeenPersist);
        if let Some(io_fault) = &fault.fault {
            return Err(seen_fault_to_error(io_fault));
        }
        if fault.corruption.is_some() {
            return Err(SpillError::Io(io::Error::other(
                "simulated seen-bitmap persistence corruption",
            )));
        }

        let mut log = self.log.borrow_mut();
        for oid in oids {
            log.push(SimPersistOp {
                phase: PersistPhase::SeenDelta,
                key: oid.as_slice().to_vec(),
                value: Vec::new(),
            });
        }
        Ok(())
    }
}

impl PersistenceStore for SimPersistStore {
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        self.apply_finalize(output)
    }
}

fn seen_fault_to_error(fault: &GitIoFault) -> SpillError {
    SpillError::Io(match fault {
        GitIoFault::ErrKind { kind } => {
            io::Error::other(format!("simulated seen-persist fault kind {kind}"))
        }
        GitIoFault::EIntrOnce => io::Error::new(
            io::ErrorKind::Interrupted,
            "simulated seen-persist interrupt",
        ),
        GitIoFault::PartialRead { max_len } => io::Error::other(format!(
            "simulated seen-persist partial write (max_len {max_len})"
        )),
    })
}

fn fault_to_error(fault: &GitIoFault) -> PersistError {
    match fault {
        GitIoFault::ErrKind { kind } => PersistError::io(io::Error::other(format!(
            "simulated persistence fault kind {kind}"
        ))),
        GitIoFault::EIntrOnce => PersistError::io(io::Error::new(
            io::ErrorKind::Interrupted,
            "simulated persistence interrupt",
        )),
        GitIoFault::PartialRead { max_len } => PersistError::backend(format!(
            "simulated persistence partial write (max_len {max_len})"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalize::{FinalizeOutcome, FinalizeOutput, FinalizeStats, WriteOp};
    use crate::persist::persist_finalize_output;

    fn output_with_ops(outcome: FinalizeOutcome) -> FinalizeOutput {
        FinalizeOutput {
            data_ops: vec![WriteOp {
                key: b"data\0".to_vec(),
                value: vec![1],
            }],
            watermark_ops: vec![WriteOp {
                key: b"wm\0".to_vec(),
                value: vec![2],
            }],
            outcome,
            stats: FinalizeStats::default(),
        }
    }

    #[test]
    fn persistence_failure_is_atomic() {
        let plan = GitFaultPlan {
            resources: vec![super::super::fault::GitResourceFaults {
                resource: GitResourceId::Persist,
                reads: vec![super::super::fault::GitReadFault {
                    fault: Some(GitIoFault::ErrKind { kind: 1 }),
                    latency_ticks: 0,
                    corruption: None,
                }],
            }],
        };

        let store = SimPersistStore::new(plan);
        let output = output_with_ops(FinalizeOutcome::Complete);
        let result = persist_finalize_output(&store, &output);
        assert!(result.is_err(), "expected persistence failure");

        let log = store.log();
        assert!(log.is_empty());
    }

    #[test]
    fn partial_outcome_never_writes_watermarks() {
        let store = SimPersistStore::default();
        let output = output_with_ops(FinalizeOutcome::Partial { skipped_count: 1 });
        let result = persist_finalize_output(&store, &output);
        assert!(matches!(result, Ok(FinalizeOutcome::Partial { .. })));

        let log = store.log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].phase, PersistPhase::Data);
    }
}
