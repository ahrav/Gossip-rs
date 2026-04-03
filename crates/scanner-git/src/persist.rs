//! Persistence store contract and helpers.
//!
//! This module defines the finalize persistence API plus incremental
//! seen-bitmap durability used during spill flushing. Finalize persistence must
//! commit data and watermark ops atomically to prevent advancing ref tips past
//! unscanned blobs.
//!
//! # Atomic contract
//! - `data_ops` are always safe to write.
//! - `watermark_ops` are only written for `FinalizeOutcome::Complete`.
//! - Implementations must commit the combined operation atomically so that
//!   readers never observe watermarks without the corresponding data writes.

#[cfg(feature = "rocksdb")]
use std::collections::HashMap;

use super::errors::{PersistError, SpillError};
#[cfg(feature = "rocksdb")]
use super::finalize::{build_seen_scope_key, NS_SEEN_BLOB};
use super::finalize::{FinalizeOutcome, FinalizeOutput, WriteOp};
#[cfg(feature = "rocksdb")]
use super::roaring_seen::{RoaringSeenBitmap, SeenBitmapDelta};
use super::seen_store::SeenBitmapPersister;
#[cfg(feature = "rocksdb")]
use super::seen_store::SeenBlobStore;

/// Persistence store interface for finalize output.
///
/// Implementations must commit `data_ops` and (when complete) `watermark_ops`
/// in a single atomic write. On partial runs, `watermark_ops` must be ignored,
/// ensuring ref tips never advance past unscanned content.
///
/// The `SeenBitmapPersister` supertrait is required because the spill-flush
/// pipeline dispatches the persistence store as a seen-bitmap persister to
/// write incremental bitmap deltas between finalize calls. Whether these
/// writes are immediately visible to `batch_check_seen` or deferred until
/// `commit_finalize` is implementation-defined. Any `PersistenceStore`
/// implementation must therefore also provide seen-bitmap writes.
pub trait PersistenceStore: SeenBitmapPersister {
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
/// Each successful `persist_seen_delta` call accumulates OIDs in an internal
/// staging buffer. On a complete finalize, `commit_finalize` folds staging
/// into the live bitmap atomically; on a partial finalize, staging is
/// discarded so that skipped blobs can be re-emitted on the next run.
/// Under the `rocksdb` feature, finalize-time seen bitmap scope ops are
/// merged per key before being recorded so the log matches what a stateful
/// key/value backend would persist.
#[derive(Debug, Default)]
pub struct InMemoryPersistenceStore {
    /// Recorded data writes from successful persistence calls.
    pub data_ops: std::cell::RefCell<Vec<WriteOp>>,
    /// Recorded watermark writes from successful complete runs.
    pub watermark_ops: std::cell::RefCell<Vec<WriteOp>>,
    /// Current seen bitmap per scope key.
    #[cfg(feature = "rocksdb")]
    seen_scopes: std::cell::RefCell<HashMap<Vec<u8>, RoaringSeenBitmap>>,
    /// Staging buffer for incremental seen-bitmap deltas not yet folded into
    /// `seen_scopes`. `commit_finalize` merges staging into the live bitmap.
    #[cfg(feature = "rocksdb")]
    seen_staging: std::cell::RefCell<HashMap<Vec<u8>, RoaringSeenBitmap>>,
    /// Optional default scope for incremental seen-bitmap writes.
    #[cfg(feature = "rocksdb")]
    seen_scope_key: Option<Vec<u8>>,
}

impl InMemoryPersistenceStore {
    /// Creates a store with a fixed seen-bitmap scope for incremental writes.
    #[cfg(feature = "rocksdb")]
    #[must_use]
    pub fn with_seen_scope(repo_id: u64, policy_hash: [u8; 32]) -> Self {
        Self {
            data_ops: std::cell::RefCell::new(Vec::new()),
            watermark_ops: std::cell::RefCell::new(Vec::new()),
            seen_scopes: std::cell::RefCell::new(HashMap::new()),
            seen_staging: std::cell::RefCell::new(HashMap::new()),
            seen_scope_key: Some(build_seen_scope_key(repo_id, &policy_hash)),
        }
    }

    #[cfg(feature = "rocksdb")]
    fn active_seen_scope_key(&self) -> Option<Vec<u8>> {
        if let Some(scope_key) = self.seen_scope_key.as_ref() {
            return Some(scope_key.clone());
        }
        let scopes = self.seen_scopes.borrow();
        if scopes.len() == 1 {
            scopes.keys().next().cloned()
        } else {
            None
        }
    }
}

impl SeenBitmapPersister for InMemoryPersistenceStore {
    fn persist_seen_delta(&self, oids: &[super::object_id::OidBytes]) -> Result<(), SpillError> {
        #[cfg(feature = "rocksdb")]
        {
            if oids.is_empty() {
                return Ok(());
            }

            let Some(scope_key) = self.active_seen_scope_key() else {
                return Err(SpillError::Io(std::io::Error::other(
                    "InMemoryPersistenceStore: no seen scope key configured; \
                     use with_seen_scope() for incremental persistence",
                )));
            };
            let delta = SeenBitmapDelta::from_canonical_oids(oids.to_vec())?;
            let mut staging = self.seen_staging.borrow_mut();
            let bitmap = staging
                .entry(scope_key)
                .or_insert_with(|| RoaringSeenBitmap::new(delta.oid_len()));
            if bitmap.oid_len() != delta.oid_len() {
                return Err(SpillError::Io(std::io::Error::other(format!(
                    "seen-bitmap OID length mismatch: stored={}, incoming={}",
                    bitmap.oid_len(),
                    delta.oid_len()
                ))));
            }
            bitmap.merge_delta(&delta)?;
            Ok(())
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = oids;
            Ok(())
        }
    }
}

#[cfg(feature = "rocksdb")]
impl SeenBlobStore for InMemoryPersistenceStore {
    fn batch_check_seen(
        &self,
        oids: &[super::object_id::OidBytes],
    ) -> Result<Vec<bool>, SpillError> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }

        let Some(scope_key) = self.active_seen_scope_key() else {
            return Ok(vec![false; oids.len()]);
        };
        let scopes = self.seen_scopes.borrow();
        let Some(bitmap) = scopes.get(&scope_key) else {
            return Ok(vec![false; oids.len()]);
        };
        if bitmap.oid_len() != oids[0].len() {
            return Err(SpillError::Io(std::io::Error::other(format!(
                "seen-bitmap OID length mismatch: stored={}, requested={}",
                bitmap.oid_len(),
                oids[0].len()
            ))));
        }
        Ok(bitmap.batch_contains_sorted(oids))
    }
}

impl PersistenceStore for InMemoryPersistenceStore {
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        // Stage all changes before committing so a mid-loop error does not
        // leave partially applied ops in the store. This preserves the
        // atomic commit contract: either all ops land or none do.
        let mut staged_data: Vec<WriteOp> = Vec::with_capacity(output.data_ops.len());
        #[cfg(feature = "rocksdb")]
        let mut seen_scope_key: Option<Vec<u8>> = None;
        #[cfg(feature = "rocksdb")]
        let mut staged_scopes: HashMap<Vec<u8>, RoaringSeenBitmap> =
            self.seen_scopes.borrow().clone();

        // Fold staging bitmaps into staged_scopes only for complete runs.
        // On partial finalize, staging may contain OIDs for blobs that were
        // emitted but later skipped. Folding those would permanently hide
        // them from future scans. Staging is always cleared regardless.
        #[cfg(feature = "rocksdb")]
        let is_complete = matches!(output.outcome, FinalizeOutcome::Complete);
        #[cfg(feature = "rocksdb")]
        {
            if is_complete {
                let staging = self.seen_staging.borrow();
                for (key, staging_bm) in staging.iter() {
                    let bitmap = staged_scopes
                        .entry(key.clone())
                        .or_insert_with(|| RoaringSeenBitmap::new(staging_bm.oid_len()));
                    bitmap
                        .merge(staging_bm)
                        .map_err(|err| PersistError::backend(err.to_string()))?;
                }
                drop(staging);
            }
        }

        for op in &output.data_ops {
            #[cfg(feature = "rocksdb")]
            if op.key.starts_with(&NS_SEEN_BLOB) {
                let delta = SeenBitmapDelta::deserialize(&op.value)
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                // Skip empty deltas to avoid seeding the scope with a
                // particular OID length when no OIDs are actually present.
                // Matches the RocksDB store's empty-delta skip.
                if delta.is_empty() {
                    continue;
                }
                // Reject batches with multiple distinct scope keys,
                // matching the RocksDB store's single-scope invariant.
                if let Some(existing) = seen_scope_key.as_ref() {
                    if existing != &op.key {
                        return Err(PersistError::backend(
                            "multiple seen-bitmap scope keys in one finalize batch",
                        ));
                    }
                } else {
                    seen_scope_key = Some(op.key.clone());
                }
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
                    .merge_delta(&delta)
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

        // Emit WriteOps for staging-only scope keys not already covered by
        // data_ops. Only for complete runs — partial discards staging.
        #[cfg(feature = "rocksdb")]
        if is_complete {
            let staging = self.seen_staging.borrow();
            for key in staging.keys() {
                if !staged_data.iter().any(|w| w.key == *key) {
                    if let Some(bitmap) = staged_scopes.get(key) {
                        let serialized = bitmap
                            .serialize()
                            .map_err(|err| PersistError::backend(err.to_string()))?;
                        staged_data.push(WriteOp {
                            key: key.clone(),
                            value: serialized,
                        });
                    }
                }
            }
            drop(staging);
        }

        // All ops validated — commit atomically.
        self.data_ops.borrow_mut().extend(staged_data);
        #[cfg(feature = "rocksdb")]
        {
            *self.seen_scopes.borrow_mut() = staged_scopes;
            self.seen_staging.borrow_mut().clear();
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

    #[cfg(feature = "rocksdb")]
    #[test]
    fn in_memory_store_skips_empty_delta_before_seeding_scope() {
        use crate::roaring_seen::RoaringSeenBitmap;

        let store = InMemoryPersistenceStore::default();
        let scope_key = build_seen_scope_key(42, &[0xAB; 32]);

        // Craft an empty SHA-1 delta (oid_count=0) followed by a real
        // SHA-256 delta. Without the empty-delta skip, the empty SHA-1
        // delta would seed the scope with oid_len=20 and the SHA-256
        // delta would fail with an OID-length mismatch.
        let empty_sha1_bytes = {
            let mut buf = Vec::with_capacity(9);
            buf.extend_from_slice(b"RSBD"); // DELTA_MAGIC
            buf.push(OidBytes::SHA1_LEN);
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf
        };
        let sha256_delta =
            SeenBitmapDelta::from_oids(&[OidBytes::sha256([0xAA; 32])]).expect("delta");

        let output = FinalizeOutput {
            data_ops: vec![
                WriteOp {
                    key: scope_key.clone(),
                    value: empty_sha1_bytes,
                },
                WriteOp {
                    key: scope_key.clone(),
                    value: sha256_delta.serialize(),
                },
            ],
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        };

        store
            .commit_finalize(&output)
            .expect("empty delta must not seed scope with wrong OID length");

        let logged = store.data_ops.borrow();
        let scope_ops: Vec<&WriteOp> = logged.iter().filter(|w| w.key == scope_key).collect();
        assert_eq!(scope_ops.len(), 1);
        let bitmap = RoaringSeenBitmap::deserialize(&scope_ops[0].value).expect("bitmap");
        assert!(bitmap.contains(&OidBytes::sha256([0xAA; 32])));
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn in_memory_store_rollback_on_failed_commit() {
        use crate::roaring_seen::RoaringSeenBitmap;

        let store = InMemoryPersistenceStore::default();
        let scope_key = build_seen_scope_key(42, &[0xAB; 32]);
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);
        let oid_c = OidBytes::sha1([0x33; 20]);

        // Seed the scope with OID A.
        store
            .commit_finalize(&seen_output(&[oid_a]))
            .expect("seed commit");

        // Attempt a batch where the first op adds OID B but the second
        // op carries a corrupt payload. Staging must discard both ops.
        let valid_delta = SeenBitmapDelta::from_oids(&[oid_b]).expect("delta b");
        let output = FinalizeOutput {
            data_ops: vec![
                WriteOp {
                    key: scope_key.clone(),
                    value: valid_delta.serialize(),
                },
                WriteOp {
                    key: scope_key.clone(),
                    value: b"corrupt-payload".to_vec(),
                },
            ],
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        };

        assert!(
            store.commit_finalize(&output).is_err(),
            "corrupt op must fail"
        );

        // The store must still contain only OID A — OID B from the failed
        // batch must not have been committed.
        let logged = store.data_ops.borrow();
        let scope_ops: Vec<&WriteOp> = logged.iter().filter(|w| w.key == scope_key).collect();
        assert_eq!(scope_ops.len(), 1, "failed commit must not add new ops");
        let bitmap = RoaringSeenBitmap::deserialize(&scope_ops[0].value).expect("bitmap");
        assert!(bitmap.contains(&oid_a), "OID A must still be present");
        assert!(
            !bitmap.contains(&oid_b),
            "OID B must not appear after rollback"
        );
        drop(logged);

        // A subsequent valid commit must merge correctly from the
        // pre-failure state, proving staged_scopes was never applied.
        store
            .commit_finalize(&seen_output(&[oid_c]))
            .expect("recovery commit");

        let logged = store.data_ops.borrow();
        let scope_ops: Vec<&WriteOp> = logged.iter().filter(|w| w.key == scope_key).collect();
        assert_eq!(scope_ops.len(), 2, "recovery commit adds one op");
        let bitmap = RoaringSeenBitmap::deserialize(&scope_ops[1].value).expect("bitmap");
        assert!(bitmap.contains(&oid_a), "OID A present after recovery");
        assert!(
            !bitmap.contains(&oid_b),
            "OID B still absent after recovery"
        );
        assert!(bitmap.contains(&oid_c), "OID C present after recovery");
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn in_memory_store_rejects_multi_scope_finalize() {
        let store = InMemoryPersistenceStore::default();

        let scope_a = build_seen_scope_key(1, &[0xAA; 32]);
        let scope_b = build_seen_scope_key(2, &[0xBB; 32]);

        let delta_a = SeenBitmapDelta::from_oids(&[OidBytes::sha1([0x11; 20])]).expect("a");
        let delta_b = SeenBitmapDelta::from_oids(&[OidBytes::sha1([0x22; 20])]).expect("b");

        let output = FinalizeOutput {
            data_ops: vec![
                WriteOp {
                    key: scope_a,
                    value: delta_a.serialize(),
                },
                WriteOp {
                    key: scope_b,
                    value: delta_b.serialize(),
                },
            ],
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        };

        let err = store
            .commit_finalize(&output)
            .expect_err("mixed scope keys must be rejected");
        assert!(
            err.to_string().contains("multiple seen-bitmap scope keys"),
            "unexpected error: {err}"
        );
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn in_memory_store_staging_deltas_invisible_until_finalize() {
        use crate::seen_store::SeenBlobStore;

        let store = InMemoryPersistenceStore::with_seen_scope(42, [0xAB; 32]);
        let scope_key = build_seen_scope_key(42, &[0xAB; 32]);
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);
        let oid_c = OidBytes::sha1([0x33; 20]);

        // Staging writes are invisible to batch_check_seen.
        store
            .persist_seen_delta(&[oid_a, oid_b])
            .expect("first incremental write");
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, oid_c])
                .expect("pre-finalize check"),
            vec![false, false, false]
        );

        // Finalize folds staging into the live bitmap.
        let empty_finalize = FinalizeOutput {
            data_ops: Vec::new(),
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        };
        store
            .commit_finalize(&empty_finalize)
            .expect("first finalize");
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, oid_c])
                .expect("post-finalize check"),
            vec![true, true, false]
        );
        // Staging must be cleared after a successful finalize.
        assert!(
            store.seen_staging.borrow().is_empty(),
            "staging must be cleared after complete finalize"
        );

        // Second round: more staging, then finalize again.
        store
            .persist_seen_delta(&[oid_b, oid_c])
            .expect("second incremental write");
        store
            .commit_finalize(&empty_finalize)
            .expect("second finalize");
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, oid_c])
                .expect("final check"),
            vec![true, true, true]
        );
        assert!(
            store.seen_staging.borrow().is_empty(),
            "staging must be cleared after second finalize"
        );

        // Each finalize produces a merged bitmap WriteOp for the scope key.
        let logged = store.data_ops.borrow();
        let scope_ops: Vec<&WriteOp> = logged.iter().filter(|w| w.key == scope_key).collect();
        assert_eq!(
            scope_ops.len(),
            2,
            "expected one logged write per finalize call"
        );
        let bitmap = RoaringSeenBitmap::deserialize(&scope_ops[1].value).expect("bitmap");
        assert!(bitmap.contains(&oid_a));
        assert!(bitmap.contains(&oid_b));
        assert!(bitmap.contains(&oid_c));
    }

    /// Incremental `persist_seen_delta` writes during spill followed by
    /// `commit_finalize` (which carries its own seen-bitmap ops) must produce
    /// the union of both OID sets in the final bitmap.
    #[cfg(feature = "rocksdb")]
    #[test]
    fn incremental_deltas_merged_with_finalize_seen_ops() {
        use crate::seen_store::SeenBlobStore;

        let store = InMemoryPersistenceStore::with_seen_scope(42, [0xAB; 32]);
        let scope_key = build_seen_scope_key(42, &[0xAB; 32]);

        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);
        let oid_c = OidBytes::sha1([0x33; 20]);
        let oid_d = OidBytes::sha1([0x44; 20]);

        // Simulate two incremental spill-time writes.
        store
            .persist_seen_delta(&[oid_a, oid_b])
            .expect("first incremental write");
        store
            .persist_seen_delta(&[oid_c])
            .expect("second incremental write");

        // Staged OIDs are invisible until finalize folds them.
        let flags = store
            .batch_check_seen(&[oid_a, oid_b, oid_c, oid_d])
            .expect("pre-finalize check");
        assert_eq!(flags, vec![false, false, false, false]);

        // Build a finalize output with seen-bitmap ops that overlap (oid_b)
        // and introduce a new OID (oid_d).
        let finalize_delta = SeenBitmapDelta::from_oids(&[oid_b, oid_d]).expect("finalize delta");
        let output = FinalizeOutput {
            data_ops: vec![WriteOp {
                key: scope_key.clone(),
                value: finalize_delta.serialize(),
            }],
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        };
        store
            .commit_finalize(&output)
            .expect("finalize with seen-bitmap ops");

        // The final bitmap must contain the union: {A, B, C, D}.
        let scopes = store.seen_scopes.borrow();
        let bitmap = scopes.get(&scope_key).expect("scope must exist");
        assert!(
            bitmap.contains(&oid_a),
            "OID A from first incremental write"
        );
        assert!(bitmap.contains(&oid_b), "OID B present in both paths");
        assert!(
            bitmap.contains(&oid_c),
            "OID C from second incremental write"
        );
        assert!(bitmap.contains(&oid_d), "OID D from finalize ops");
        drop(scopes);

        // batch_check_seen must agree with the bitmap state.
        let flags = store
            .batch_check_seen(&[oid_a, oid_b, oid_c, oid_d])
            .expect("batch check");
        assert_eq!(flags, vec![true, true, true, true]);

        // Staging must be cleared after a successful finalize.
        assert!(
            store.seen_staging.borrow().is_empty(),
            "staging must be cleared after complete finalize"
        );
    }

    /// Partial finalize discards staging so that skipped blobs are
    /// re-emittable on the next run. Only the `data_ops` seen delta
    /// (successfully scanned blobs) enters the live bitmap.
    #[cfg(feature = "rocksdb")]
    #[test]
    fn partial_finalize_discards_staging() {
        use crate::seen_store::SeenBlobStore;

        let store = InMemoryPersistenceStore::with_seen_scope(42, [0xAB; 32]);
        let scope_key = build_seen_scope_key(42, &[0xAB; 32]);

        let oid_staged = OidBytes::sha1([0x11; 20]);
        let oid_scanned = OidBytes::sha1([0x22; 20]);

        // Simulate spill: stage oid_staged.
        store
            .persist_seen_delta(&[oid_staged])
            .expect("spill write");

        // Partial finalize: only oid_scanned appears in data_ops.
        let delta = SeenBitmapDelta::from_oids(&[oid_scanned]).expect("delta");
        let output = FinalizeOutput {
            data_ops: vec![WriteOp {
                key: scope_key.clone(),
                value: delta.serialize(),
            }],
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Partial { skipped_count: 1 },
            stats: FinalizeStats::default(),
        };
        store.commit_finalize(&output).expect("partial finalize");

        // oid_scanned should be seen (from data_ops).
        // oid_staged should NOT be seen (staging discarded on partial).
        let flags = store
            .batch_check_seen(&[oid_staged, oid_scanned])
            .expect("check after partial finalize");
        assert_eq!(
            flags,
            vec![false, true],
            "staged OID must not be promoted on partial finalize"
        );

        // Staging buffer must be cleared.
        assert!(
            store.seen_staging.borrow().is_empty(),
            "staging must be cleared after partial finalize"
        );
    }
}
