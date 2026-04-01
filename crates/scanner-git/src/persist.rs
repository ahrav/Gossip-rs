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

#[cfg(feature = "rocksdb")]
use std::collections::HashMap;

use super::errors::PersistError;
#[cfg(feature = "rocksdb")]
use super::finalize::NS_SEEN_BLOB;
use super::finalize::{FinalizeOutcome, FinalizeOutput, WriteOp};
#[cfg(feature = "rocksdb")]
use super::roaring_seen::{RoaringSeenBitmap, SeenBitmapDelta};

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
/// Each commit appends to the stored ops. Under the `rocksdb` feature, seen
/// bitmap scope ops are merged per key before being recorded so the log matches
/// what a stateful key/value backend would persist.
#[derive(Debug, Default)]
pub struct InMemoryPersistenceStore {
    /// Recorded data writes from successful finalize calls.
    pub data_ops: std::cell::RefCell<Vec<WriteOp>>,
    /// Recorded watermark writes from successful complete runs.
    pub watermark_ops: std::cell::RefCell<Vec<WriteOp>>,
    /// Current seen bitmap per scope key.
    #[cfg(feature = "rocksdb")]
    seen_scopes: std::cell::RefCell<HashMap<Vec<u8>, RoaringSeenBitmap>>,
}

impl PersistenceStore for InMemoryPersistenceStore {
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        let mut data_ops = self.data_ops.borrow_mut();
        #[cfg(feature = "rocksdb")]
        let mut seen_scopes = self.seen_scopes.borrow_mut();

        for op in &output.data_ops {
            #[cfg(feature = "rocksdb")]
            if op.key.starts_with(&NS_SEEN_BLOB) {
                let delta = SeenBitmapDelta::deserialize(&op.value)
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                let mut bitmap = seen_scopes
                    .remove(&op.key)
                    .unwrap_or_else(|| RoaringSeenBitmap::new(delta.oid_len()));
                if bitmap.oid_len() != delta.oid_len() {
                    bitmap = RoaringSeenBitmap::new(delta.oid_len());
                }
                bitmap
                    .insert_batch(delta.oids())
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                let merged = bitmap.serialize();
                seen_scopes.insert(op.key.clone(), bitmap);
                data_ops.push(WriteOp {
                    key: op.key.clone(),
                    value: merged,
                });
                continue;
            }

            data_ops.push(op.clone());
        }
        if matches!(output.outcome, FinalizeOutcome::Complete) {
            self.watermark_ops
                .borrow_mut()
                .extend_from_slice(&output.watermark_ops);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalize::{build_seen_scope_key, FinalizeStats};
    use crate::object_id::OidBytes;

    #[cfg(feature = "rocksdb")]
    use crate::roaring_seen::SeenBitmapDelta;

    #[cfg(feature = "rocksdb")]
    fn seen_output(oids: &[OidBytes]) -> FinalizeOutput {
        FinalizeOutput {
            data_ops: vec![WriteOp {
                key: build_seen_scope_key(42, &[0xAB; 32]),
                value: SeenBitmapDelta::from_oids(oids).expect("delta").serialize(),
            }],
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        }
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn in_memory_store_merges_seen_scope_writes() {
        let store = InMemoryPersistenceStore::default();
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);
        let oid_c = OidBytes::sha1([0x33; 20]);

        store
            .commit_finalize(&seen_output(&[oid_a, oid_b]))
            .expect("first commit");
        store
            .commit_finalize(&seen_output(&[oid_b, oid_c]))
            .expect("second commit");

        let logged = store.data_ops.borrow();
        let latest = logged.last().expect("merged scope op");
        let bitmap = RoaringSeenBitmap::deserialize(&latest.value).expect("bitmap");
        assert!(bitmap.contains(&oid_a));
        assert!(bitmap.contains(&oid_b));
        assert!(bitmap.contains(&oid_c));
    }
}
