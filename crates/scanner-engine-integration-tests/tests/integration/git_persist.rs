//! Integration tests for persistence ordering and atomicity.
//!
//! These tests exercise the finalize persistence contract:
//! - Data ops are always written.
//! - Watermark ops are only written on complete runs.
//! - Errors surface without recording partial writes.

use std::cell::Cell;

use scanner_git::{
    FinalizeOutcome, FinalizeOutput, FinalizeStats, OidBytes, PersistError, PersistenceStore,
    SeenBitmapPersister, SpillError, WriteOp, persist_finalize_output,
};

/// Test double that records persisted ops and can simulate commit failures.
#[derive(Default)]
struct RecordingStore {
    /// Recorded data writes from successful commits.
    data_ops: std::cell::RefCell<Vec<WriteOp>>,
    /// Recorded watermark writes from successful complete commits.
    watermark_ops: std::cell::RefCell<Vec<WriteOp>>,
    /// Tracks how many commit attempts were made.
    commit_calls: Cell<u32>,
    /// Forces `commit_finalize` to fail before recording any ops.
    fail_commit: Cell<bool>,
}

impl PersistenceStore for RecordingStore {
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        // Count calls even when the commit is configured to fail.
        self.commit_calls
            .set(self.commit_calls.get().saturating_add(1));
        if self.fail_commit.get() {
            // Simulate a backend failure before any writes are recorded.
            return Err(PersistError::backend("commit failed"));
        }
        self.data_ops
            .borrow_mut()
            .extend_from_slice(&output.data_ops);
        if matches!(output.outcome, FinalizeOutcome::Complete) {
            self.watermark_ops
                .borrow_mut()
                .extend_from_slice(&output.watermark_ops);
        }
        Ok(())
    }
}

impl SeenBitmapPersister for RecordingStore {
    fn persist_seen_delta(&self, _oids: &[OidBytes]) -> Result<(), SpillError> {
        Ok(())
    }
}

#[test]
fn complete_run_commits_data_and_watermarks() {
    let store = RecordingStore::default();
    let output = FinalizeOutput {
        data_ops: vec![WriteOp {
            key: vec![1],
            value: vec![1],
        }],
        watermark_ops: vec![WriteOp {
            key: vec![2],
            value: vec![2],
        }],
        outcome: FinalizeOutcome::Complete,
        stats: FinalizeStats::default(),
    };

    let res = persist_finalize_output(&store, &output).unwrap();
    assert_eq!(res, FinalizeOutcome::Complete);
    assert_eq!(store.commit_calls.get(), 1);
    assert_eq!(store.data_ops.borrow().len(), 1);
    assert_eq!(store.watermark_ops.borrow().len(), 1);
}

#[test]
fn partial_runs_commit_data_only() {
    let store = RecordingStore::default();
    let output = FinalizeOutput {
        data_ops: vec![WriteOp {
            key: vec![1],
            value: vec![1],
        }],
        watermark_ops: vec![WriteOp {
            key: vec![2],
            value: vec![2],
        }],
        outcome: FinalizeOutcome::Partial { skipped_count: 2 },
        stats: FinalizeStats::default(),
    };

    let res = persist_finalize_output(&store, &output).unwrap();
    assert_eq!(res, FinalizeOutcome::Partial { skipped_count: 2 });
    assert_eq!(store.commit_calls.get(), 1);
    assert_eq!(store.data_ops.borrow().len(), 1);
    assert!(store.watermark_ops.borrow().is_empty());
}

#[test]
fn failed_commit_writes_nothing() {
    let store = RecordingStore::default();
    store.fail_commit.set(true);
    let output = FinalizeOutput {
        data_ops: vec![WriteOp {
            key: vec![1],
            value: vec![1],
        }],
        watermark_ops: vec![WriteOp {
            key: vec![2],
            value: vec![2],
        }],
        outcome: FinalizeOutcome::Complete,
        stats: FinalizeStats::default(),
    };

    let err = persist_finalize_output(&store, &output).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("commit failed"));
    assert_eq!(store.commit_calls.get(), 1);
    assert!(store.data_ops.borrow().is_empty());
    assert!(store.watermark_ops.borrow().is_empty());
}
