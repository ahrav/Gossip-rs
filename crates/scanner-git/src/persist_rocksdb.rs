//! RocksDB-backed persistence adapters.
//!
//! This module is feature-gated. Enable with `--features rocksdb`.
//! The adapter uses a single RocksDB instance with plain key/value pairs.
//! Ref watermarks still use sorted `multi_get` access, while seen-blob queries
//! are served from a lazily loaded in-memory bitmap snapshot.
//! Incremental seen-bitmap updates use single-key `put` writes during spill
//! flushing. Finalize output is committed with a single `WriteBatch` so data
//! writes and watermarks become visible atomically.
//! When the feature is disabled, public constructors and methods return
//! feature-not-available errors via the appropriate error variant.

#[cfg(feature = "rocksdb")]
use std::cell::{Cell, RefCell};
use std::io;
use std::path::Path;

use super::errors::{PersistError, RepoOpenError, SpillError};
#[cfg(feature = "rocksdb")]
use super::finalize::FinalizeOutcome;
use super::finalize::FinalizeOutput;
#[cfg(feature = "rocksdb")]
use super::finalize::NS_SEEN_BLOB;
#[cfg(feature = "rocksdb")]
use super::finalize::{build_ref_wm_key, build_seen_scope_key};
use super::object_id::OidBytes;
use super::persist::PersistenceStore;
use super::repo_open::RefWatermarkStore;
#[cfg(feature = "rocksdb")]
use super::roaring_seen::{RoaringSeenBitmap, RoaringSeenStore, SeenBitmapDelta};
use super::seen_store::{SeenBitmapPersister, SeenBlobStore};
use super::start_set::StartSetId;
#[cfg(feature = "rocksdb")]
use super::watermark_keys::decode_ref_watermark_value;

#[cfg(feature = "rocksdb")]
use rocksdb::{Options, WriteBatch, DB};

/// RocksDB-backed store for Git scan persistence.
///
/// All access is single-threaded: the scan pipeline calls `batch_check_seen`
/// and `persist_seen_delta` during the spill stage (before parallel pack
/// execution) and `commit_finalize` once after all workers join. `RefCell`
/// enforces this contract at runtime; a borrow panic indicates a caller bug.
///
/// The store retains the `repo_id` and `policy_hash` used to build
/// the seen-bitmap scope key for the spill/dedupe stage.
/// Watermark loading uses the caller-supplied `(repo_id, policy_hash)` so the
/// same RocksDB instance can serve multiple namespaces if needed. Callers must
/// supply the same tuple used when writing watermarks to read consistent data.
#[derive(Debug)]
pub struct RocksDbStore {
    #[cfg(feature = "rocksdb")]
    db: DB,
    #[cfg(feature = "rocksdb")]
    repo_id: u64,
    #[cfg(feature = "rocksdb")]
    policy_hash: [u8; 32],
    #[cfg(feature = "rocksdb")]
    seen_store: RefCell<Option<RoaringSeenStore>>,
    /// Set during `commit_finalize` to detect re-entrant calls in debug builds.
    /// The single-writer invariant (one lease owner per scope) guarantees this
    /// never trips in production; if it does, the caller has a lease bug.
    #[cfg(feature = "rocksdb")]
    finalizing: Cell<bool>,
}

impl RocksDbStore {
    /// Opens or creates a RocksDB database at the given path.
    ///
    /// The provided `repo_id` and `policy_hash` are stored on the handle and
    /// used to locate the seen-bitmap scope and ref-watermark namespace.
    /// When the `rocksdb` feature is disabled, this returns a backend error.
    ///
    /// # Errors
    /// Returns a backend error when RocksDB cannot be opened or the feature is
    /// disabled.
    pub fn open(
        path: impl AsRef<Path>,
        repo_id: u64,
        policy_hash: [u8; 32],
    ) -> Result<Self, PersistError> {
        #[cfg(feature = "rocksdb")]
        {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            let db = DB::open(&opts, path).map_err(|err| PersistError::backend(err.to_string()))?;
            Ok(Self {
                db,
                repo_id,
                policy_hash,
                seen_store: RefCell::new(None),
                finalizing: Cell::new(false),
            })
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = (path, repo_id, policy_hash);
            Err(PersistError::backend("rocksdb support not enabled"))
        }
    }

    #[cfg(feature = "rocksdb")]
    fn load_seen_store(&self, oid_len: u8) -> Result<(), String> {
        let needs_load = self
            .seen_store
            .borrow()
            .as_ref()
            .is_none_or(|s| s.bitmap().oid_len() != oid_len);
        if needs_load {
            let loaded = self.load_seen_store_from_db(oid_len)?;
            *self.seen_store.borrow_mut() = Some(loaded);
        }
        Ok(())
    }

    #[cfg(feature = "rocksdb")]
    fn load_seen_store_from_db(&self, oid_len: u8) -> Result<RoaringSeenStore, String> {
        let scope_key = build_seen_scope_key(self.repo_id, &self.policy_hash);
        match self.db.get(&scope_key) {
            Ok(Some(bytes)) => match RoaringSeenBitmap::deserialize(bytes.as_ref()) {
                Ok(bitmap) if bitmap.oid_len() == oid_len => Ok(RoaringSeenStore::new(bitmap)),
                Ok(bitmap) => Err(format!(
                    "seen-bitmap OID length mismatch: stored={}, requested={}",
                    bitmap.oid_len(),
                    oid_len
                )),
                Err(err) => Err(format!("corrupt seen-bitmap: {err}")),
            },
            Ok(None) => Ok(RoaringSeenStore::new(RoaringSeenBitmap::new(oid_len))),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Writes the seen-bitmap delta to RocksDB outside the atomic `WriteBatch`
    /// used by `commit_finalize`.
    ///
    /// # Crash-consistency trade-off
    ///
    /// This write advances the persisted seen-bitmap independently of ref
    /// watermarks. If the process crashes after this `put` but before
    /// `commit_finalize` atomically writes watermarks, recovery will observe
    /// blobs marked as seen whose scan findings were never committed. Those
    /// blobs will be skipped on the next run. This is intentional: it avoids
    /// expensive re-scanning at the cost of potentially missing findings for
    /// blobs processed during the incomplete run. The trade-off is acceptable
    /// because the incremental bitmap is a best-effort deduplication hint, not
    /// a correctness-critical data structure.
    /// Merges `delta` into the in-memory bitmap in-place, serializes, and
    /// writes the result to RocksDB.
    ///
    /// The bitmap is mutated before the `db.put` call. If `db.put` fails, the
    /// in-memory bitmap contains mutations that are not persisted — the same
    /// trade-off documented on `commit_finalize` for the atomic `WriteBatch`
    /// path. This is acceptable because the seen-bitmap is a best-effort
    /// deduplication hint, not a correctness-critical structure.
    #[cfg(feature = "rocksdb")]
    fn persist_seen_delta_inner(&self, delta: &SeenBitmapDelta) -> Result<(), String> {
        let scope_key = build_seen_scope_key(self.repo_id, &self.policy_hash);
        self.load_seen_store(delta.oid_len())?;

        // Mutate the bitmap in-place and serialize while holding the borrow.
        // The borrow is dropped before the I/O call to avoid holding the
        // RefCell across `db.put`.
        let bytes = {
            let mut guard = self.seen_store.borrow_mut();
            let store = guard.as_mut().ok_or_else(|| {
                "incremental seen-bitmap persist failed: seen-store not initialized".to_string()
            })?;
            store
                .bitmap_mut()
                .merge_delta(delta)
                .map_err(|err| format!("incremental seen-bitmap merge failed: {err}"))?;
            store
                .bitmap()
                .serialize()
                .map_err(|err| format!("incremental seen-bitmap serialization failed: {err}"))?
        };

        self.db
            .put(&scope_key, &bytes)
            .map_err(|err| format!("incremental seen-bitmap RocksDB put failed: {err}"))?;
        Ok(())
    }
}

impl SeenBitmapPersister for RocksDbStore {
    fn persist_seen_delta(&self, oids: &[OidBytes]) -> Result<(), SpillError> {
        #[cfg(feature = "rocksdb")]
        {
            if oids.is_empty() {
                return Ok(());
            }

            let delta = SeenBitmapDelta::from_canonical_oids(oids.to_vec()).map_err(|err| {
                SpillError::Io(io::Error::other(format!(
                    "seen-bitmap delta construction failed: {err}"
                )))
            })?;
            self.persist_seen_delta_inner(&delta)
                .map_err(|err| SpillError::Io(io::Error::other(err)))?;
            Ok(())
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = oids;
            Err(SpillError::Io(io::Error::other(
                "rocksdb support not enabled",
            )))
        }
    }
}

impl PersistenceStore for RocksDbStore {
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        #[cfg(feature = "rocksdb")]
        {
            // Guard that clears the `finalizing` flag on all exit paths,
            // including early error returns.
            struct FinalizingGuard<'a>(&'a Cell<bool>);
            impl Drop for FinalizingGuard<'_> {
                fn drop(&mut self) {
                    self.0.set(false);
                }
            }
            debug_assert!(
                !self.finalizing.replace(true),
                "re-entrant commit_finalize calls violate the single-writer invariant"
            );
            let _guard = FinalizingGuard(&self.finalizing);

            debug_assert!(
                output.data_ops.windows(2).all(|w| w[0].key <= w[1].key),
                "data ops must be sorted by key"
            );
            debug_assert!(
                output
                    .watermark_ops
                    .windows(2)
                    .all(|w| w[0].key <= w[1].key),
                "watermark ops must be sorted by key"
            );
            debug_assert!(
                matches!(output.outcome, FinalizeOutcome::Complete)
                    || output.watermark_ops.is_empty(),
                "watermark ops present for partial outcome"
            );
            let mut batch = WriteBatch::default();
            let mut seen_scope_key: Option<Vec<u8>> = None;
            let mut seen_oids = Vec::new();
            for op in &output.data_ops {
                if op.key.starts_with(&NS_SEEN_BLOB) {
                    let delta = SeenBitmapDelta::deserialize(&op.value)
                        .map_err(|err| PersistError::backend(err.to_string()))?;
                    if delta.is_empty() {
                        continue;
                    }
                    if let Some(existing_key) = seen_scope_key.as_ref() {
                        if existing_key != &op.key {
                            return Err(PersistError::backend(
                                "multiple seen-bitmap scope keys in one finalize batch",
                            ));
                        }
                    } else {
                        seen_scope_key = Some(op.key.clone());
                    }
                    seen_oids.extend_from_slice(delta.oids());
                } else {
                    batch.put(&op.key, &op.value);
                }
            }

            // Staged bitmap built from a clone of the cache. Applied to the
            // in-memory cache only after db.write succeeds, so a write failure
            // leaves the cache consistent with what is persisted.
            let mut staged_bitmap: Option<RoaringSeenBitmap> = None;

            if !seen_oids.is_empty() {
                // Multiple same-scope deltas may have individually sorted OID
                // lists, but their concatenation is not necessarily globally
                // sorted. Use `from_oids` to sort and dedup the combined set.
                let delta = SeenBitmapDelta::from_oids(&seen_oids)
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                self.load_seen_store(delta.oid_len())
                    .map_err(PersistError::backend)?;

                // Validate that the scope key matches this store's identity.
                // The multi-scope check above ensures all ops share one key,
                // but that key must also match the store's repo_id/policy_hash
                // to prevent cross-scope pollution.
                let scope_key = seen_scope_key
                    .as_ref()
                    .ok_or_else(|| PersistError::backend("seen-bitmap delta without scope key"))?;
                let expected_scope_key = build_seen_scope_key(self.repo_id, &self.policy_hash);
                if *scope_key != expected_scope_key {
                    return Err(PersistError::backend(
                        "seen-bitmap scope key does not match store identity",
                    ));
                }

                // Build the merged bitmap in a separate clone so the in-memory
                // cache is not mutated until db.write succeeds. This prevents
                // divergence between the cache and the persisted state on write
                // failure.
                let merged = {
                    let guard = self.seen_store.borrow();
                    let base = guard.as_ref().map_or_else(
                        || RoaringSeenBitmap::new(delta.oid_len()),
                        |s| s.bitmap().clone(),
                    );
                    let mut staged = base;
                    // The finalize-time merge may re-apply OIDs already present
                    // from incremental persistence. This is harmless: merge_delta
                    // is a set-union and the cost is bounded by the delta size.
                    staged
                        .merge_delta(&delta)
                        .map_err(|err| PersistError::backend(err.to_string()))?;
                    staged
                };
                let serialized = merged
                    .serialize()
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                batch.put(scope_key, serialized);
                staged_bitmap = Some(merged);
            }

            if matches!(output.outcome, FinalizeOutcome::Complete) {
                for op in &output.watermark_ops {
                    batch.put(&op.key, &op.value);
                }
            }
            self.db
                .write(batch)
                .map_err(|err| PersistError::backend(err.to_string()))?;

            // Promote the staged bitmap into the cache only after the write
            // succeeds. On failure the cache retains the pre-finalize state.
            if let Some(bitmap) = staged_bitmap {
                *self.seen_store.borrow_mut() = Some(RoaringSeenStore::new(bitmap));
            }

            Ok(())
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = output;
            Err(PersistError::backend("rocksdb support not enabled"))
        }
    }
}

impl SeenBlobStore for RocksDbStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        #[cfg(feature = "rocksdb")]
        {
            if oids.is_empty() {
                return Ok(Vec::new());
            }

            let oid_len = oids[0].len();
            self.load_seen_store(oid_len)
                .map_err(|err| SpillError::Io(io::Error::other(err)))?;
            let guard = self.seen_store.borrow();
            let Some(store) = guard.as_ref() else {
                return Err(SpillError::Io(io::Error::other(
                    "seen-store not initialized",
                )));
            };
            store.batch_check_seen(oids)
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = oids;
            Err(SpillError::Io(io::Error::other(
                "rocksdb support not enabled",
            )))
        }
    }
}

impl RefWatermarkStore for RocksDbStore {
    fn load_watermarks(
        &self,
        repo_id: u64,
        policy_hash: [u8; 32],
        start_set_id: StartSetId,
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        #[cfg(feature = "rocksdb")]
        {
            // `ref_names` are expected to be sorted to preserve key ordering.
            // Results mirror the input order with `None` for missing entries.
            let mut keys = Vec::with_capacity(ref_names.len());
            for name in ref_names {
                keys.push(build_ref_wm_key(repo_id, &policy_hash, &start_set_id, name));
            }
            debug_assert!(
                keys.windows(2).all(|w| w[0] <= w[1]),
                "watermark keys must be sorted"
            );

            let results = self.db.multi_get(keys.iter());
            let mut out = Vec::with_capacity(results.len());
            for res in results {
                match res {
                    Ok(Some(val)) => {
                        let decoded =
                            decode_ref_watermark_value(val.as_ref()).ok_or_else(|| {
                                RepoOpenError::io(io::Error::other(
                                    "invalid watermark value encoding",
                                ))
                            })?;
                        out.push(Some(decoded));
                    }
                    Ok(None) => out.push(None),
                    Err(err) => return Err(RepoOpenError::io(io::Error::other(err.to_string()))),
                }
            }
            Ok(out)
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = (repo_id, policy_hash, start_set_id, ref_names);
            Err(RepoOpenError::io(io::Error::other(
                "rocksdb support not enabled",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalize::{build_seen_scope_key, FinalizeStats, WriteOp};

    #[cfg(feature = "rocksdb")]
    use tempfile::tempdir;

    #[cfg(feature = "rocksdb")]
    fn seen_finalize_output(
        repo_id: u64,
        policy_hash: [u8; 32],
        oids: &[OidBytes],
    ) -> FinalizeOutput {
        let delta = SeenBitmapDelta::from_oids(oids).expect("delta");
        FinalizeOutput {
            data_ops: vec![WriteOp {
                key: build_seen_scope_key(repo_id, &policy_hash),
                value: delta.serialize(),
            }],
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        }
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_store_commit_finalize_merges_seen_bitmap_scope() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 7;
        let policy_hash = [0x55; 32];
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);
        let oid_c = OidBytes::sha1([0x33; 20]);

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        store
            .commit_finalize(&seen_finalize_output(repo_id, policy_hash, &[oid_a, oid_b]))
            .expect("first commit");
        drop(store);

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("reopen");
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, oid_c])
                .expect("batch check"),
            vec![true, true, false]
        );
        store
            .commit_finalize(&seen_finalize_output(repo_id, policy_hash, &[oid_b, oid_c]))
            .expect("second commit");
        drop(store);

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("reopen again");
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, oid_c])
                .expect("batch check"),
            vec![true, true, true]
        );
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_store_rejects_corrupt_bitmap_on_load() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 11;
        let policy_hash = [0xCC; 32];

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        let scope_key = build_seen_scope_key(repo_id, &policy_hash);
        store
            .db
            .put(&scope_key, b"not-a-valid-bitmap")
            .expect("seed corrupt data");

        let err = store
            .batch_check_seen(&[OidBytes::sha1([0x01; 20])])
            .expect_err("corrupt bitmap should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("corrupt seen-bitmap"),
            "error should mention corruption, got: {msg}"
        );
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_store_rejects_oid_length_mismatch_on_load() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 12;
        let policy_hash = [0xDD; 32];

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        // Persist a SHA-1 bitmap.
        store
            .commit_finalize(&seen_finalize_output(
                repo_id,
                policy_hash,
                &[OidBytes::sha1([0x11; 20])],
            ))
            .expect("commit sha1 bitmap");
        drop(store);

        // Reopen and query with SHA-256 OIDs — the stored bitmap has
        // oid_len=20 but the query requests oid_len=32.
        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("reopen");
        let err = store
            .batch_check_seen(&[OidBytes::sha256([0x22; 32])])
            .expect_err("OID length mismatch should fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("mismatch"),
            "error should mention mismatch, got: {msg}"
        );
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_store_rejects_multi_scope_finalize() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 13;
        let policy_hash_a = [0xAA; 32];
        let policy_hash_b = [0xBB; 32];

        let oids_a = vec![OidBytes::sha1([0x11; 20])];
        let oids_b = vec![OidBytes::sha1([0x22; 20])];
        let delta_a = SeenBitmapDelta::from_oids(&oids_a).expect("delta a");
        let delta_b = SeenBitmapDelta::from_oids(&oids_b).expect("delta b");

        // Build a FinalizeOutput with two data_ops that carry different scope
        // keys (different policy_hash). The store must reject this because a
        // single finalize batch should never span multiple scopes.
        let output = FinalizeOutput {
            data_ops: vec![
                WriteOp {
                    key: build_seen_scope_key(repo_id, &policy_hash_a),
                    value: delta_a.serialize(),
                },
                WriteOp {
                    key: build_seen_scope_key(repo_id, &policy_hash_b),
                    value: delta_b.serialize(),
                },
            ],
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        };

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash_a).expect("open");
        let err = store
            .commit_finalize(&output)
            .expect_err("multi-scope finalize must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("multiple seen-bitmap scope keys"),
            "error should mention multiple scope keys, got: {msg}"
        );
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_store_handles_multi_delta_same_scope() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 16;
        let policy_hash = [0xEE; 32];

        // Two deltas with the same scope key but interleaving OID ranges.
        // Delta 1: [0x30, 0x40] (sorted within)
        // Delta 2: [0x10, 0x20] (sorted within)
        // Concatenation: [0x30, 0x40, 0x10, 0x20] — NOT globally sorted.
        let oids_high = vec![OidBytes::sha1([0x30; 20]), OidBytes::sha1([0x40; 20])];
        let oids_low = vec![OidBytes::sha1([0x10; 20]), OidBytes::sha1([0x20; 20])];
        let delta_high = SeenBitmapDelta::from_oids(&oids_high).expect("delta high");
        let delta_low = SeenBitmapDelta::from_oids(&oids_low).expect("delta low");

        let scope_key = build_seen_scope_key(repo_id, &policy_hash);
        let output = FinalizeOutput {
            data_ops: vec![
                WriteOp {
                    key: scope_key.clone(),
                    value: delta_high.serialize(),
                },
                WriteOp {
                    key: scope_key,
                    value: delta_low.serialize(),
                },
            ],
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        };

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        store
            .commit_finalize(&output)
            .expect("multi-delta same-scope commit");

        assert_eq!(
            store
                .batch_check_seen(&[
                    OidBytes::sha1([0x10; 20]),
                    OidBytes::sha1([0x20; 20]),
                    OidBytes::sha1([0x30; 20]),
                    OidBytes::sha1([0x40; 20]),
                ])
                .expect("batch check"),
            vec![true, true, true, true]
        );
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_store_oid_len_mismatch_returns_error() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 15;
        let policy_hash = [0xDD; 32];

        // Commit SHA-1 OIDs.
        let sha1_oid = OidBytes::sha1([0x11; 20]);
        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        store
            .commit_finalize(&seen_finalize_output(repo_id, policy_hash, &[sha1_oid]))
            .expect("commit SHA-1");
        assert_eq!(
            store.batch_check_seen(&[sha1_oid]).expect("check SHA-1"),
            vec![true],
            "SHA-1 OID should be seen after commit"
        );
        drop(store);

        // Reopen and query with SHA-256 OIDs. The store holds a SHA-1 bitmap
        // on disk, but the queried OID length differs. This must return an
        // error rather than silently discarding the persisted bitmap.
        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("reopen");
        let sha256_oid = OidBytes::sha256([0x22; 32]);
        let err = store
            .batch_check_seen(&[sha256_oid])
            .expect_err("OID length mismatch should return error");
        let msg = format!("{err}");
        assert!(
            msg.contains("mismatch"),
            "error should mention mismatch, got: {msg}"
        );
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_store_incremental_seen_delta_survives_reopen_without_watermarks() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 17;
        let policy_hash = [0xAA; 32];
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);
        let oid_c = OidBytes::sha1([0x33; 20]);
        let start_set_id: StartSetId = [0x44; 32];

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        store
            .persist_seen_delta(&[oid_a, oid_b])
            .expect("incremental persist");
        let seen_scope_key = build_seen_scope_key(repo_id, &policy_hash);
        assert!(
            store
                .db
                .get(&seen_scope_key)
                .expect("seen scope lookup")
                .is_some(),
            "incremental persist should write the seen scope key"
        );
        let watermark_key =
            build_ref_wm_key(repo_id, &policy_hash, &start_set_id, b"refs/heads/main");
        assert!(
            store
                .db
                .get(&watermark_key)
                .expect("watermark lookup")
                .is_none(),
            "incremental persist must not write watermarks"
        );
        drop(store);

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("reopen");
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, oid_c])
                .expect("batch check"),
            vec![true, true, false]
        );
    }
}
