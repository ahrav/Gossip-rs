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
        // Stage all changes before committing so a mid-loop error does not
        // leave partially applied ops in the store. This preserves the
        // atomic commit contract: either all ops land or none do.
        let mut staged_data: Vec<WriteOp> = Vec::with_capacity(output.data_ops.len());
        #[cfg(feature = "rocksdb")]
        let mut staged_scopes: HashMap<Vec<u8>, RoaringSeenBitmap> =
            self.seen_scopes.borrow().clone();

        for op in &output.data_ops {
            #[cfg(feature = "rocksdb")]
            if op.key.starts_with(&NS_SEEN_BLOB) {
                let delta = SeenBitmapDelta::deserialize(&op.value)
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                let mut bitmap = staged_scopes
                    .remove(&op.key)
                    .unwrap_or_else(|| RoaringSeenBitmap::new(delta.oid_len()));
                if bitmap.oid_len() != delta.oid_len() {
                    return Err(PersistError::backend(format!(
                        "seen-bitmap OID length mismatch: stored={}, incoming={}",
                        bitmap.oid_len(),
                        delta.oid_len()
                    )));
                }
                bitmap
                    .insert_batch(delta.oids())
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                let merged = bitmap
                    .serialize()
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                staged_scopes.insert(op.key.clone(), bitmap);
                // Collapse same-scope deltas to a single logged write,
                // matching the RocksDB store which emits one put per scope.
                if let Some(existing) = staged_data.iter_mut().find(|w| w.key == op.key) {
                    existing.value = merged;
                } else {
                    staged_data.push(WriteOp {
                        key: op.key.clone(),
                        value: merged,
                    });
                }
                continue;
            }

            staged_data.push(op.clone());
        }

        // All ops validated — commit atomically.
        self.data_ops.borrow_mut().extend(staged_data);
        #[cfg(feature = "rocksdb")]
        {
            *self.seen_scopes.borrow_mut() = staged_scopes;
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

    #[cfg(feature = "rocksdb")]
    #[test]
    fn in_memory_store_collapses_same_scope_deltas_to_one_write() {
        use crate::roaring_seen::RoaringSeenBitmap;

        let store = InMemoryPersistenceStore::default();
        let scope_key = build_seen_scope_key(42, &[0xAB; 32]);

        // Two deltas for the same scope key in a single commit.
        let delta_a = SeenBitmapDelta::from_oids(&[OidBytes::sha1([0x11; 20])]).expect("a");
        let delta_b = SeenBitmapDelta::from_oids(&[OidBytes::sha1([0x22; 20])]).expect("b");

        let output = FinalizeOutput {
            data_ops: vec![
                WriteOp {
                    key: scope_key.clone(),
                    value: delta_a.serialize(),
                },
                WriteOp {
                    key: scope_key.clone(),
                    value: delta_b.serialize(),
                },
            ],
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        };

        store.commit_finalize(&output).expect("commit");

        // Only one WriteOp should be logged for the scope key, containing
        // the fully merged bitmap — matching RocksDB store behavior.
        let logged = store.data_ops.borrow();
        let scope_ops: Vec<&WriteOp> = logged.iter().filter(|w| w.key == scope_key).collect();
        assert_eq!(
            scope_ops.len(),
            1,
            "expected one collapsed WriteOp per scope key, got {}",
            scope_ops.len()
        );

        let bitmap = RoaringSeenBitmap::deserialize(&scope_ops[0].value).expect("bitmap");
        assert!(bitmap.contains(&OidBytes::sha1([0x11; 20])));
        assert!(bitmap.contains(&OidBytes::sha1([0x22; 20])));
    }
}
