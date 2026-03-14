//! Persistence store contract and helpers.
//!
//! This module defines the write-only persistence API used after finalize.
//! Persistence must commit data and watermark ops atomically to prevent
//! advancing ref tips past unscanned blobs.
//!
//! # Atomic contract
//! - `data_ops` are always safe to write.
//! - `watermark_ops` are only written for `FinalizeOutcome::Complete`.
//! - Implementations must commit the combined operation atomically so that
//!   readers never observe watermarks without the corresponding data writes.

use super::errors::PersistError;
use super::finalize::{FinalizeOutcome, FinalizeOutput, WriteOp};

/// Persistence store interface for finalize output.
///
/// Implementations must commit `data_ops` and (when complete) `watermark_ops`
/// in a single atomic write. On partial runs, `watermark_ops` must be ignored,
/// ensuring ref tips never advance past unscanned content.
pub trait PersistenceStore {
    /// Commits finalize output atomically.
    ///
    /// Implementations may assume ops are pre-sorted by key for performance
    /// diagnostics, but must not require ordering for correctness.
    /// Implementations must ignore `watermark_ops` when the outcome is partial.
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError>;
}

/// Persist finalize output with atomic semantics.
///
/// This helper forwards to the store and returns the outcome on success so
/// callers can update control flow without re-inspecting `FinalizeOutput`.
pub fn persist_finalize_output(
    store: &dyn PersistenceStore,
    output: &FinalizeOutput,
) -> Result<FinalizeOutcome, PersistError> {
    store.commit_finalize(output)?;
    Ok(output.outcome)
}

/// In-memory persistence store for tests and diagnostics.
///
/// The store records committed ops for later inspection and intentionally
/// skips synchronization; it uses `RefCell` for interior mutability and is not
/// thread-safe.
///
/// Each commit appends to the stored ops; no dedupe is performed.
#[derive(Debug, Default)]
pub struct InMemoryPersistenceStore {
    /// Recorded data writes from successful finalize calls.
    pub data_ops: std::cell::RefCell<Vec<WriteOp>>,
    /// Recorded watermark writes from successful complete runs.
    pub watermark_ops: std::cell::RefCell<Vec<WriteOp>>,
}

impl PersistenceStore for InMemoryPersistenceStore {
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
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
