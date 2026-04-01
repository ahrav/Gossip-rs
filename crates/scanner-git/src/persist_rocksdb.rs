//! RocksDB-backed persistence adapters.
//!
//! This module is feature-gated. Enable with `--features rocksdb`.
//! The adapter uses a single RocksDB instance with plain key/value pairs.
//! Ref watermarks still use sorted `multi_get` access, while seen-blob queries
//! are served from a lazily loaded in-memory bitmap snapshot.
//! Finalize output is committed with a single `WriteBatch` so data writes and
//! watermarks become visible atomically.
//! When the feature is disabled, public constructors and methods return
//! feature-not-available errors via the appropriate error variant.

use std::io;
use std::path::Path;
#[cfg(feature = "rocksdb")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "rocksdb")]
use std::sync::RwLock;

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
use super::seen_store::SeenBlobStore;
use super::start_set::StartSetId;
#[cfg(feature = "rocksdb")]
use super::watermark_keys::decode_ref_watermark_value;

#[cfg(feature = "rocksdb")]
use rocksdb::{Options, WriteBatch, DB};

/// RocksDB-backed store for Git scan persistence.
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
    seen_store: RwLock<Option<RoaringSeenStore>>,
    /// Set during `commit_finalize` to detect concurrent calls in debug builds.
    /// The single-writer invariant (one lease owner per scope) guarantees this
    /// never trips in production; if it does, the caller has a lease bug.
    #[cfg(feature = "rocksdb")]
    finalizing: AtomicBool,
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
                seen_store: RwLock::new(None),
                finalizing: AtomicBool::new(false),
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
        {
            let guard = self
                .seen_store
                .read()
                .map_err(|_| "seen-store read lock poisoned".to_string())?;
            if let Some(store) = guard.as_ref() {
                if store.bitmap().oid_len() == oid_len {
                    return Ok(());
                }
            }
        }

        let mut guard = self
            .seen_store
            .write()
            .map_err(|_| "seen-store write lock poisoned".to_string())?;
        if let Some(store) = guard.as_ref() {
            if store.bitmap().oid_len() == oid_len {
                return Ok(());
            }
        }

        *guard = Some(self.load_seen_store_from_db(oid_len)?);
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
}

impl PersistenceStore for RocksDbStore {
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        #[cfg(feature = "rocksdb")]
        {
            // Guard that clears the `finalizing` flag on all exit paths,
            // including early error returns.
            struct FinalizingGuard<'a>(&'a AtomicBool);
            impl Drop for FinalizingGuard<'_> {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Relaxed);
                }
            }
            debug_assert!(
                !self.finalizing.swap(true, Ordering::Relaxed),
                "concurrent commit_finalize calls violate the single-writer invariant"
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
            // Declared outside the conditional so the write lock can be held
            // through db.write, preventing readers from observing in-memory
            // mutations before they are persisted to disk.
            let mut _seen_guard: Option<std::sync::RwLockWriteGuard<'_, Option<RoaringSeenStore>>> =
                None;
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

                // Hold the write lock through the entire
                // read-modify-write-persist cycle so concurrent readers
                // (batch_check_seen) never observe uncommitted mutations.
                let mut guard = self
                    .seen_store
                    .write()
                    .map_err(|_| PersistError::backend("seen-store write lock poisoned"))?;
                let store = guard.get_or_insert_with(|| {
                    RoaringSeenStore::new(RoaringSeenBitmap::new(delta.oid_len()))
                });

                store
                    .bitmap_mut()
                    .insert_batch(delta.oids())
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                batch.put(
                    scope_key,
                    store
                        .bitmap()
                        .serialize()
                        .map_err(|err| PersistError::backend(err.to_string()))?,
                );
                // Move the write guard out so it is held through db.write
                // below. Without this, a concurrent batch_check_seen could
                // observe the in-memory mutation before it is persisted.
                _seen_guard = Some(guard);
            }

            if matches!(output.outcome, FinalizeOutcome::Complete) {
                for op in &output.watermark_ops {
                    batch.put(&op.key, &op.value);
                }
            }
            self.db
                .write(batch)
                .map_err(|err| PersistError::backend(err.to_string()))?;
            // Write lock (if held) drops here after db.write succeeds,
            // keeping the in-memory bitmap consistent with on-disk state.
            // NOTE: if db.write fails, the in-memory bitmap retains
            // uncommitted mutations; the caller must discard the store.
            drop(_seen_guard);
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
            let guard = self
                .seen_store
                .read()
                .map_err(|_| SpillError::Io(io::Error::other("seen-store read lock poisoned")))?;
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
}
