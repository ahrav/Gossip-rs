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
#[cfg(any(feature = "rocksdb", test))]
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
use rocksdb::{Direction, IteratorMode, Options, WriteBatch, DB};

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

/// Returns the byte length of a seen-blob key for the given OID length.
#[cfg(test)]
fn seen_blob_key_len(oid_len: u8) -> usize {
    3 + 8 + 32 + oid_len as usize
}

/// Writes a `seen_blob` key into the provided buffer.
///
/// Layout: namespace prefix + repo_id + policy_hash + oid bytes.
#[cfg(test)]
fn write_seen_blob_key(buf: &mut [u8], repo_id: u64, policy_hash: &[u8; 32], oid: &OidBytes) {
    debug_assert_eq!(buf.len(), seen_blob_key_len(oid.len()));
    let mut offset = 0;
    buf[offset..offset + 3].copy_from_slice(&NS_SEEN_BLOB);
    offset += 3;
    buf[offset..offset + 8].copy_from_slice(&repo_id.to_be_bytes());
    offset += 8;
    buf[offset..offset + 32].copy_from_slice(policy_hash);
    offset += 32;
    buf[offset..offset + oid.len() as usize].copy_from_slice(oid.as_slice());
}

/// Returns the byte length of the seen-bitmap scope key.
#[cfg(test)]
fn seen_scope_key_len() -> usize {
    3 + 8 + 32
}

/// Writes the seen-bitmap scope key into the provided buffer.
#[cfg(test)]
fn write_seen_scope_key(buf: &mut [u8], repo_id: u64, policy_hash: &[u8; 32]) {
    debug_assert_eq!(buf.len(), seen_scope_key_len());
    let mut offset = 0;
    buf[offset..offset + 3].copy_from_slice(&NS_SEEN_BLOB);
    offset += 3;
    buf[offset..offset + 8].copy_from_slice(&repo_id.to_be_bytes());
    offset += 8;
    buf[offset..offset + 32].copy_from_slice(policy_hash);
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
            Ok(None) => self.migrate_legacy_seen_keys(oid_len, &scope_key),
            Err(err) => Err(err.to_string()),
        }
    }

    #[cfg(feature = "rocksdb")]
    fn migrate_legacy_seen_keys(
        &self,
        oid_len: u8,
        scope_key: &[u8],
    ) -> Result<RoaringSeenStore, String> {
        let mut migrated_keys = Vec::new();
        let mut skipped_keys: usize = 0;
        let mut legacy_oids = Vec::new();

        for item in self
            .db
            .full_iterator(IteratorMode::From(scope_key, Direction::Forward))
        {
            let (key, _) = item.map_err(|err| err.to_string())?;
            if !key.starts_with(scope_key) {
                break;
            }
            if key.len() == scope_key.len() {
                continue;
            }

            let suffix = &key[scope_key.len()..];
            if suffix.len() == oid_len as usize {
                if let Some(oid) = OidBytes::try_from_slice(suffix) {
                    legacy_oids.push(oid);
                    migrated_keys.push(key.to_vec());
                    continue;
                }
            }
            // Key has an unexpected suffix length or failed OID parsing;
            // leave it in place rather than silently deleting it.
            skipped_keys += 1;
        }

        if migrated_keys.is_empty() {
            if skipped_keys > 0 {
                return Err(format!(
                    "migration found {skipped_keys} legacy seen keys with \
                     unexpected suffix length (expected {oid_len}); \
                     no keys were migrated or deleted"
                ));
            }
            return Ok(RoaringSeenStore::new(RoaringSeenBitmap::new(oid_len)));
        }

        let mut bitmap = RoaringSeenBitmap::new(oid_len);
        bitmap
            .insert_batch(&legacy_oids)
            .map_err(|err| err.to_string())?;

        let mut batch = WriteBatch::default();
        if !bitmap.is_empty() {
            batch.put(
                scope_key,
                bitmap.serialize().map_err(|err| err.to_string())?,
            );
        }
        for key in &migrated_keys {
            batch.delete(key);
        }
        self.db.write(batch).map_err(|err| err.to_string())?;

        Ok(RoaringSeenStore::new(bitmap))
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
                // OIDs were deserialized from a single canonical delta (the
                // multi-scope check above rejects batches with different scope
                // keys), so they are already sorted and unique.
                let delta = SeenBitmapDelta::from_canonical_oids(seen_oids)
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                self.load_seen_store(delta.oid_len())
                    .map_err(PersistError::backend)?;

                // Hold the write lock for the entire read-modify-write-persist
                // cycle. The single-writer invariant (one lease owner per scope)
                // means no contention on the write lock, so holding it through
                // serialization and db.write avoids cloning the bitmap.
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
                let scope_key = seen_scope_key
                    .as_ref()
                    .ok_or_else(|| PersistError::backend("seen-bitmap delta without scope key"))?;
                batch.put(
                    scope_key,
                    store
                        .bitmap()
                        .serialize()
                        .map_err(|err| PersistError::backend(err.to_string()))?,
                );
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
    use crate::finalize::{build_seen_blob_key, build_seen_scope_key, FinalizeStats, WriteOp};

    #[cfg(feature = "rocksdb")]
    use tempfile::tempdir;

    #[test]
    fn seen_blob_key_builder_matches_legacy() {
        let repo_id = 42;
        let policy_hash = [0xAB; 32];
        let oid = OidBytes::sha1([0x11; 20]);

        let expected = build_seen_blob_key(repo_id, &policy_hash, &oid);
        let mut buf = vec![0u8; seen_blob_key_len(oid.len())];
        write_seen_blob_key(&mut buf, repo_id, &policy_hash, &oid);

        assert_eq!(buf, expected);
    }

    #[test]
    fn seen_scope_key_builder_matches_finalize() {
        let repo_id = 42;
        let policy_hash = [0xCD; 32];

        let expected = build_seen_scope_key(repo_id, &policy_hash);
        let mut buf = vec![0u8; seen_scope_key_len()];
        write_seen_scope_key(&mut buf, repo_id, &policy_hash);

        assert_eq!(buf, expected);
    }

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
    fn rocksdb_store_migrates_per_oid_seen_keys() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 9;
        let policy_hash = [0x99; 32];
        let oid_a = OidBytes::sha1([0x0A; 20]);
        let oid_b = OidBytes::sha1([0x0B; 20]);
        let legacy_scope_key = build_seen_scope_key(repo_id, &policy_hash);

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        let mut batch = WriteBatch::default();
        batch.put(build_seen_blob_key(repo_id, &policy_hash, &oid_a), [1u8]);
        batch.put(build_seen_blob_key(repo_id, &policy_hash, &oid_b), [1u8]);
        store.db.write(batch).expect("seed legacy keys");

        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, OidBytes::sha1([0x0C; 20])])
                .expect("batch check"),
            vec![true, true, false]
        );

        let bitmap_bytes = store
            .db
            .get(&legacy_scope_key)
            .expect("read scope key")
            .expect("scope key present");
        let bitmap = RoaringSeenBitmap::deserialize(bitmap_bytes.as_ref()).expect("bitmap");
        assert!(bitmap.contains(&oid_a));
        assert!(bitmap.contains(&oid_b));
        assert!(
            store
                .db
                .get(build_seen_blob_key(repo_id, &policy_hash, &oid_a))
                .expect("read legacy key")
                .is_none(),
            "legacy per-OID keys should be removed during migration"
        );
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_store_migration_preserves_unrecognized_keys() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 10;
        let policy_hash = [0xBB; 32];
        let oid_a = OidBytes::sha1([0x0A; 20]);

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        let scope_key = build_seen_scope_key(repo_id, &policy_hash);

        // Seed one valid SHA-1 legacy key and one key with wrong suffix
        // length (5 bytes instead of 20).
        let mut batch = WriteBatch::default();
        batch.put(build_seen_blob_key(repo_id, &policy_hash, &oid_a), [1u8]);
        let mut bad_key = scope_key.to_vec();
        bad_key.extend_from_slice(&[0xFF; 5]);
        batch.put(&bad_key, [1u8]);
        store.db.write(batch).expect("seed mixed keys");

        // Migration should succeed: the valid key is migrated, the
        // unrecognized key is left in place.
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, OidBytes::sha1([0x0B; 20])])
                .expect("batch check"),
            vec![true, false]
        );

        // The valid legacy key should be deleted.
        assert!(
            store
                .db
                .get(build_seen_blob_key(repo_id, &policy_hash, &oid_a))
                .expect("read migrated key")
                .is_none(),
            "migrated key should be deleted"
        );

        // The unrecognized key should still exist.
        assert!(
            store.db.get(&bad_key).expect("read bad key").is_some(),
            "unrecognized key should be preserved"
        );
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn rocksdb_store_migration_errors_when_only_unrecognized_keys_exist() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 10;
        let policy_hash = [0xBC; 32];

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        let scope_key = build_seen_scope_key(repo_id, &policy_hash);

        // Seed only keys with wrong suffix length.
        let mut bad_key = scope_key.to_vec();
        bad_key.extend_from_slice(&[0xFF; 5]);
        store.db.put(&bad_key, [1u8]).expect("seed bad key");

        let err = store
            .batch_check_seen(&[OidBytes::sha1([0x01; 20])])
            .expect_err("should fail when only unrecognized keys exist");
        let msg = format!("{err}");
        assert!(
            msg.contains("unexpected suffix length"),
            "error should mention unexpected suffix, got: {msg}"
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
