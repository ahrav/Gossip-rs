//! RocksDB-backed persistence adapters.
//!
//! This module is feature-gated. Enable with `--features rocksdb`.
//! The adapter uses a single RocksDB instance with plain key/value pairs.
//! Ref watermarks still use sorted `multi_get` access, while seen-blob queries
//! are served from a lazily loaded in-memory bitmap snapshot.
//! Incremental seen-bitmap updates during spill flushing write to a staging
//! key (`ss\0`). `commit_finalize` folds staging into the live scope key
//! atomically within the `WriteBatch`, so data writes, seen-bitmap merges,
//! and watermarks become visible atomically.
//! When the feature is disabled, public constructors and methods return
//! feature-not-available errors via the appropriate error variant.

#[cfg(feature = "rocksdb")]
use std::cell::{Cell, RefCell};
use std::io;
use std::path::Path;

use tracing::debug;

use super::errors::{PersistError, RepoOpenError, SpillError};
#[cfg(feature = "rocksdb")]
use super::finalize::FinalizeOutcome;
use super::finalize::FinalizeOutput;
#[cfg(feature = "rocksdb")]
use super::finalize::{
    build_ref_wm_key, build_seen_ordinal_key, build_seen_scope_key, build_seen_staging_key,
};
#[cfg(feature = "rocksdb")]
use super::finalize::{NS_SEEN_BLOB, NS_SEEN_ORDINAL};
use super::object_id::{ObjectFormat, OidBytes};
#[cfg(feature = "rocksdb")]
use super::ordinal_seen::HybridSeenStore;
use super::persist::PersistenceStore;
use super::repo_open::RefWatermarkStore;
use super::repo_open::RepoArtifactFingerprint;
#[cfg(feature = "rocksdb")]
use super::roaring_seen::{RoaringSeenBitmap, RoaringSeenStore, SeenBitmapDelta};
use super::seen_store::{SeenBitmapPersister, SeenBlobStore};
use super::start_set::StartSetId;
#[cfg(feature = "rocksdb")]
use super::watermark_keys::decode_ref_watermark_value;
use super::watermark_keys::RefWatermark;

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
    seen_store: RefCell<Option<HybridSeenStore>>,
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
            let store = Self {
                db,
                repo_id,
                policy_hash,
                seen_store: RefCell::new(None),
                finalizing: Cell::new(false),
            };
            store.cleanup_orphaned_staging()?;
            Ok(store)
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
            .is_none_or(|s| s.fallback().bitmap().oid_len() != oid_len);
        if needs_load {
            let loaded = self.load_seen_store_from_db(oid_len)?;
            *self.seen_store.borrow_mut() = Some(loaded);
        }
        Ok(())
    }

    #[cfg(feature = "rocksdb")]
    fn load_seen_store_from_db(&self, oid_len: u8) -> Result<HybridSeenStore, String> {
        let scope_key = build_seen_scope_key(self.repo_id, &self.policy_hash);
        match self.db.get(&scope_key) {
            Ok(Some(bytes)) => match RoaringSeenBitmap::deserialize(bytes.as_ref()) {
                Ok(bitmap) if bitmap.oid_len() == oid_len => {
                    Ok(HybridSeenStore::new(RoaringSeenStore::new(bitmap)))
                }
                Ok(bitmap) => Err(format!(
                    "seen-bitmap OID length mismatch: stored={}, requested={}",
                    bitmap.oid_len(),
                    oid_len
                )),
                Err(err) => Err(format!("corrupt seen-bitmap: {err}")),
            },
            Ok(None) => Ok(HybridSeenStore::new(RoaringSeenStore::new(
                RoaringSeenBitmap::new(oid_len),
            ))),
            Err(err) => Err(err.to_string()),
        }
    }

    /// Writes a seen-bitmap delta to the staging key (`ss\0`).
    ///
    /// The authoritative roaring scope remains invisible to
    /// `batch_check_seen` until `commit_finalize` folds staging into `sb\0`.
    /// When the store has been configured with the current MIDX snapshot,
    /// `persist_seen_delta` also updates the in-memory ordinal cache after the
    /// staging write succeeds so the current process can dedupe repeated
    /// MIDX-resident OIDs within the same scan. On restart, only committed
    /// state is reloaded.
    #[cfg(feature = "rocksdb")]
    fn persist_seen_delta_inner(&self, delta: &SeenBitmapDelta) -> Result<(), SpillError> {
        let staging_key = build_seen_staging_key(self.repo_id, &self.policy_hash);

        // Load any existing staging bitmap, merge the new delta, write back.
        let bytes = match self.db.get(&staging_key) {
            Ok(Some(existing)) => {
                let mut bitmap = RoaringSeenBitmap::deserialize(&existing).map_err(|err| {
                    SpillError::Io(io::Error::other(format!("corrupt staging bitmap: {err}")))
                })?;
                bitmap.merge_delta(delta)?;
                bitmap.serialize()?
            }
            Ok(None) => {
                let mut bitmap = RoaringSeenBitmap::new(delta.oid_len());
                bitmap.merge_delta(delta)?;
                bitmap.serialize()?
            }
            Err(err) => {
                return Err(SpillError::Io(io::Error::other(format!(
                    "staging bitmap read failed: {err}"
                ))));
            }
        };

        self.db.put(&staging_key, &bytes).map_err(|err| {
            SpillError::Io(io::Error::other(format!(
                "staging seen-bitmap RocksDB put failed: {err}"
            )))
        })?;
        Ok(())
    }

    /// Deletes any orphaned staging key left by a crashed previous run.
    ///
    /// Returns an error if the RocksDB delete fails, since a surviving
    /// staging key would cause the next `commit_finalize` to fold
    /// never-committed OIDs into the live bitmap.
    #[cfg(feature = "rocksdb")]
    fn cleanup_orphaned_staging(&self) -> Result<(), PersistError> {
        let staging_key = build_seen_staging_key(self.repo_id, &self.policy_hash);
        self.db
            .delete(&staging_key)
            .map_err(|err| PersistError::backend(err.to_string()))
    }
}

impl SeenBitmapPersister for RocksDbStore {
    fn persist_seen_delta(&self, oids: &[OidBytes]) -> Result<(), SpillError> {
        #[cfg(feature = "rocksdb")]
        {
            if oids.is_empty() {
                return Ok(());
            }

            let delta = SeenBitmapDelta::from_canonical_oids(oids.to_vec())?;
            self.persist_seen_delta_inner(&delta)?;
            if let Some(store) = self.seen_store.borrow_mut().as_mut() {
                store.mark_seen_batch(oids)?;
            }
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

            // The seen-store cache is moved out, updated, and restored only
            // after db.write succeeds. A failed write leaves the cache empty so
            // the next access reloads authoritative state from RocksDB.
            let mut staged_seen_store: Option<HybridSeenStore> = None;

            // Fold spill-stage staging bitmap into seen_oids only for
            // complete runs. On partial finalize, staging may contain OIDs
            // for blobs that were emitted but skipped (budget/corruption).
            // Folding those would permanently hide them from future scans
            // because `batch_check_seen` would suppress re-emission while
            // watermarks remain un-advanced.
            let staging_key = build_seen_staging_key(self.repo_id, &self.policy_hash);
            let is_complete = matches!(output.outcome, FinalizeOutcome::Complete);
            match self.db.get(&staging_key) {
                Ok(Some(staging_bytes)) => {
                    if is_complete {
                        // All OIDs in the staging bitmap are marked seen because
                        // persist_seen_delta_inner only ever merges via merge_delta,
                        // which uses `other_contains = |_| true`.
                        let staging_bitmap = RoaringSeenBitmap::deserialize(&staging_bytes)
                            .map_err(|err| {
                                PersistError::backend(format!("corrupt staging bitmap: {err}"))
                            })?;
                        if staging_bitmap.len() != staging_bitmap.index_len() {
                            return Err(PersistError::backend(
                                "staging bitmap contains unseen entries",
                            ));
                        }
                        seen_oids.extend(staging_bitmap.all_oids());
                    }
                    // Delete the staging key in both cases: complete folds
                    // it into live; partial discards it so skipped blobs
                    // can be re-emitted on the next run.
                    batch.delete(&staging_key);
                }
                Ok(None) => {}
                Err(err) => {
                    return Err(PersistError::backend(format!(
                        "staging bitmap read failed: {err}"
                    )));
                }
            }

            let had_seen_cache = self.seen_store.borrow().is_some();
            if !seen_oids.is_empty() || had_seen_cache {
                // Multiple same-scope deltas may have individually sorted OID
                // lists, but their concatenation is not necessarily globally
                // sorted. Use `from_oids` to sort and dedup the combined set.
                let delta = if seen_oids.is_empty() {
                    None
                } else {
                    Some(
                        SeenBitmapDelta::from_oids(&seen_oids)
                            .map_err(|err| PersistError::backend(err.to_string()))?,
                    )
                };

                if let Some(delta) = &delta {
                    let scope_key_for_bitmap = seen_scope_key
                        .unwrap_or_else(|| build_seen_scope_key(self.repo_id, &self.policy_hash));
                    let expected_scope_key = build_seen_scope_key(self.repo_id, &self.policy_hash);
                    if scope_key_for_bitmap != expected_scope_key {
                        return Err(PersistError::backend(
                            "seen-bitmap scope key does not match store identity",
                        ));
                    }
                    self.load_seen_store(delta.oid_len())
                        .map_err(PersistError::backend)?;
                }

                let mut guard = self.seen_store.borrow_mut();
                let Some(mut store) = guard.take() else {
                    if delta.is_some() {
                        return Err(PersistError::backend(
                            "seen-store not initialized after successful load",
                        ));
                    }
                    drop(guard);
                    unreachable!("had_seen_cache implies a cached seen store");
                };
                drop(guard);

                if let Some(delta) = &delta {
                    let scope_key_for_bitmap =
                        build_seen_scope_key(self.repo_id, &self.policy_hash);
                    store
                        .fallback_mut()
                        .bitmap_mut()
                        .merge_delta(delta)
                        .map_err(|err| PersistError::backend(err.to_string()))?;
                    let serialized = store
                        .fallback()
                        .bitmap()
                        .serialize()
                        .map_err(|err| PersistError::backend(err.to_string()))?;
                    batch.put(&scope_key_for_bitmap, serialized);
                }

                if is_complete {
                    if let Some(ordinal_bytes) = store
                        .persisted_ordinal_bytes()
                        .map_err(|err| PersistError::backend(err.to_string()))?
                    {
                        batch.put(
                            build_seen_ordinal_key(self.repo_id, &self.policy_hash),
                            ordinal_bytes,
                        );
                    }
                } else {
                    store.clear_ordinal_cache();
                }

                staged_seen_store = Some(store);
            }

            if matches!(output.outcome, FinalizeOutcome::Complete) {
                for op in &output.watermark_ops {
                    batch.put(&op.key, &op.value);
                }
            }
            self.db
                .write(batch)
                .map_err(|err| PersistError::backend(err.to_string()))?;

            // Promote the staged seen store into the cache only after the
            // write succeeds. On failure the cache is reloaded from RocksDB.
            if let Some(store) = staged_seen_store {
                *self.seen_store.borrow_mut() = Some(store);
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

    fn configure_midx_snapshot(
        &self,
        midx_bytes: super::bytes::BytesView,
        object_format: ObjectFormat,
        artifact_fingerprint: RepoArtifactFingerprint,
    ) -> Result<(), SpillError> {
        #[cfg(feature = "rocksdb")]
        {
            self.load_seen_store(object_format.oid_len())
                .map_err(|err| SpillError::Io(io::Error::other(err)))?;
            let ordinal_key = build_seen_ordinal_key(self.repo_id, &self.policy_hash);
            let ordinal_bytes = self
                .db
                .get(&ordinal_key)
                .map_err(|err| SpillError::Io(io::Error::other(err.to_string())))?;
            let mut guard = self.seen_store.borrow_mut();
            let Some(store) = guard.as_mut() else {
                return Err(SpillError::Io(io::Error::other(
                    "seen-store not initialized after successful load",
                )));
            };
            store.set_midx_snapshot(midx_bytes, object_format, artifact_fingerprint)?;
            if let Some(bytes) = ordinal_bytes {
                match store.load_persisted_ordinal(&bytes) {
                    Ok(true) => {}
                    Ok(false) => {
                        debug!("discarded stale persisted seen-ordinal cache");
                    }
                    Err(err) => {
                        debug!(error = %err, "discarded corrupt persisted seen-ordinal cache");
                        store.clear_ordinal_cache();
                    }
                }
            }
            Ok(())
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = (midx_bytes, object_format, artifact_fingerprint);
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
    ) -> Result<Vec<Option<RefWatermark>>, RepoOpenError> {
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
                        // Payloads must include the 4-byte LE generation
                        // trailer. Malformed or undersized payloads are
                        // rejected, surfacing as a RepoOpenError.
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
    use crate::finalize::{build_seen_ordinal_key, build_seen_scope_key, FinalizeStats, WriteOp};
    use crate::midx_test_builder::MidxBuilder;
    use crate::ordinal_seen::MidxOrdinalBitset;
    use crate::repo_open::RepoArtifactFingerprint;
    use crate::{BytesView, ObjectFormat};

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
    fn test_fingerprint(tag: u8) -> RepoArtifactFingerprint {
        RepoArtifactFingerprint {
            packs_hash: [tag; 32],
            idx_hash: [tag.wrapping_add(1); 32],
        }
    }

    #[cfg(feature = "rocksdb")]
    fn test_midx(values: &[u32]) -> BytesView {
        let mut builder = MidxBuilder::new();
        builder.add_pack(b"pack-0.pack");
        for &value in values {
            let mut bytes = [0u8; 20];
            bytes[..4].copy_from_slice(&value.to_be_bytes());
            builder.add_object(bytes, 0, value as u64);
        }
        BytesView::from_vec(builder.build())
    }

    #[cfg(feature = "rocksdb")]
    fn fold_fingerprint(fingerprint: &RepoArtifactFingerprint) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"scanner-git::hybrid-seen-store");
        hasher.update(&fingerprint.packs_hash);
        hasher.update(&fingerprint.idx_hash);
        *hasher.finalize().as_bytes()
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

    /// Spill-stage deltas go to the staging key, NOT the live scope key.
    /// After `commit_finalize` folds them, the OIDs become durably visible.
    #[cfg(feature = "rocksdb")]
    #[test]
    fn spill_delta_staged_then_folded_on_finalize() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 17;
        let policy_hash = [0xAA; 32];
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);
        let oid_c = OidBytes::sha1([0x33; 20]);

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        store
            .persist_seen_delta(&[oid_a, oid_b])
            .expect("spill checkpoint");

        // Staging key should exist; live scope key should NOT.
        let staging_key = build_seen_staging_key(repo_id, &policy_hash);
        let scope_key = build_seen_scope_key(repo_id, &policy_hash);
        assert!(
            store
                .db
                .get(&staging_key)
                .expect("staging lookup")
                .is_some(),
            "spill delta should write the staging key"
        );
        assert!(
            store.db.get(&scope_key).expect("scope lookup").is_none(),
            "spill delta must not write the live scope key"
        );

        // batch_check_seen must not see staged OIDs.
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b])
                .expect("check before finalize"),
            vec![false, false],
            "staged OIDs must not be visible to batch_check_seen"
        );

        // Finalize with oid_b and oid_c via data ops. The staging delta
        // (oid_a, oid_b) is folded in, so all three become seen.
        store
            .commit_finalize(&seen_finalize_output(repo_id, policy_hash, &[oid_b, oid_c]))
            .expect("finalize");

        // Staging key should be deleted after finalize.
        assert!(
            store
                .db
                .get(&staging_key)
                .expect("staging after finalize")
                .is_none(),
            "staging key must be deleted after finalize"
        );

        // Verify all three OIDs are seen in the current instance.
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, oid_c])
                .expect("check after finalize"),
            vec![true, true, true],
            "staging + finalize OIDs should all be seen"
        );

        // Verify the merged bitmap survives a restart.
        drop(store);
        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("reopen");
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, oid_c])
                .expect("batch check after reopen"),
            vec![true, true, true],
            "staging + finalize OIDs should all be seen after reopen"
        );
    }

    /// Spill-stage `persist_seen_delta` writes must not pollute the live
    /// bitmap that `batch_check_seen` reads. Otherwise a crash between
    /// spill and `commit_finalize` permanently hides blobs whose findings
    /// were never committed.
    #[cfg(feature = "rocksdb")]
    #[test]
    fn spill_checkpoint_without_finalize_must_not_pollute_live_bitmap() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 19;
        let policy_hash = [0xBB; 32];
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);

        // Simulate spill: persist_seen_delta writes OIDs during spill stage.
        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        store
            .persist_seen_delta(&[oid_a, oid_b])
            .expect("spill checkpoint");

        // Simulate crash: drop without calling commit_finalize.
        drop(store);

        // Restart: the next run must NOT see these OIDs as "seen" because
        // commit_finalize never ran — findings were never committed.
        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("reopen");

        // The orphaned staging key must have been deleted by open().
        let staging_key = build_seen_staging_key(repo_id, &policy_hash);
        assert!(
            store
                .db
                .get(&staging_key)
                .expect("staging lookup")
                .is_none(),
            "open() must delete the orphaned staging key"
        );

        let seen = store
            .batch_check_seen(&[oid_a, oid_b])
            .expect("batch check after crash");

        assert_eq!(
            seen,
            vec![false, false],
            "spill-only checkpoint without finalize must not mark OIDs as seen"
        );
    }

    /// Multiple `persist_seen_delta` calls accumulate in the staging key.
    /// `commit_finalize` folds the union into the live bitmap.
    #[cfg(feature = "rocksdb")]
    #[test]
    fn multiple_spill_deltas_accumulate_in_staging() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 20;
        let policy_hash = [0xCC; 32];
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);
        let oid_c = OidBytes::sha1([0x33; 20]);
        let oid_d = OidBytes::sha1([0x44; 20]);

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");

        // Two separate spill checkpoints with disjoint OID sets.
        store
            .persist_seen_delta(&[oid_a, oid_b])
            .expect("first spill");
        store.persist_seen_delta(&[oid_c]).expect("second spill");

        // Staging key should contain the union {A, B, C}.
        let staging_key = build_seen_staging_key(repo_id, &policy_hash);
        let staging_bytes = store
            .db
            .get(&staging_key)
            .expect("staging read")
            .expect("staging key must exist");
        let staging_bitmap =
            RoaringSeenBitmap::deserialize(&staging_bytes).expect("staging deserialize");
        assert!(staging_bitmap.contains(&oid_a));
        assert!(staging_bitmap.contains(&oid_b));
        assert!(staging_bitmap.contains(&oid_c));
        assert!(!staging_bitmap.contains(&oid_d));

        // None are visible to batch_check_seen yet.
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, oid_c])
                .expect("check before finalize"),
            vec![false, false, false],
        );

        // Finalize with oid_d only — staging {A,B,C} + finalize {D} → all seen.
        store
            .commit_finalize(&seen_finalize_output(repo_id, policy_hash, &[oid_d]))
            .expect("finalize");

        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b, oid_c, oid_d])
                .expect("check after finalize"),
            vec![true, true, true, true],
            "staging accumulation + finalize should produce the full union"
        );

        // Staging key deleted after finalize.
        assert!(
            store
                .db
                .get(&staging_key)
                .expect("staging after finalize")
                .is_none(),
            "staging key must be deleted after finalize"
        );
    }

    /// When all candidates are already seen and no new blobs are scanned,
    /// `commit_finalize` receives empty `data_ops` but the staging key
    /// still exists. The staging OIDs must land in the live bitmap.
    #[cfg(feature = "rocksdb")]
    #[test]
    fn staging_only_finalize_folds_without_data_ops() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 21;
        let policy_hash = [0xDD; 32];
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        store
            .persist_seen_delta(&[oid_a, oid_b])
            .expect("spill checkpoint");

        // Finalize with empty data_ops — only staging contributes.
        let empty_finalize = FinalizeOutput {
            data_ops: Vec::new(),
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        };
        store
            .commit_finalize(&empty_finalize)
            .expect("empty finalize");

        // Staging OIDs should now be visible.
        assert_eq!(
            store
                .batch_check_seen(&[oid_a, oid_b])
                .expect("check after empty finalize"),
            vec![true, true],
            "staging-only finalize must fold OIDs into the live bitmap"
        );

        // Staging key deleted.
        let staging_key = build_seen_staging_key(repo_id, &policy_hash);
        assert!(
            store
                .db
                .get(&staging_key)
                .expect("staging after finalize")
                .is_none(),
            "staging key must be deleted after finalize"
        );
    }

    #[cfg(feature = "rocksdb")]
    #[test]
    fn configured_store_persists_seen_ordinal_and_exposes_staged_midx_oids() {
        let dir = tempdir().expect("tempdir");
        let repo_id = 22;
        let policy_hash = [0xEE; 32];
        let fingerprint = test_fingerprint(0x22);
        let mut oid_a_bytes = [0u8; 20];
        oid_a_bytes[..4].copy_from_slice(&0x11u32.to_be_bytes());
        let oid_a = OidBytes::sha1(oid_a_bytes);

        let store = RocksDbStore::open(dir.path(), repo_id, policy_hash).expect("open");
        store
            .configure_midx_snapshot(
                test_midx(&[0x11, 0x22, 0x33]),
                ObjectFormat::Sha1,
                fingerprint.clone(),
            )
            .expect("configure midx");

        store.persist_seen_delta(&[oid_a]).expect("stage oid");
        assert_eq!(
            store
                .batch_check_seen(&[oid_a])
                .expect("staged oid should be visible in-process"),
            vec![true]
        );

        let empty_finalize = FinalizeOutput {
            data_ops: Vec::new(),
            watermark_ops: Vec::new(),
            outcome: FinalizeOutcome::Complete,
            stats: FinalizeStats::default(),
        };
        store
            .commit_finalize(&empty_finalize)
            .expect("complete finalize");

        let ordinal_key = build_seen_ordinal_key(repo_id, &policy_hash);
        let ordinal_bytes = store
            .db
            .get(&ordinal_key)
            .expect("ordinal lookup")
            .expect("ordinal key must exist after complete finalize");
        let ordinal = MidxOrdinalBitset::deserialize(&ordinal_bytes).expect("ordinal decode");
        assert_eq!(ordinal.midx_fingerprint(), &fold_fingerprint(&fingerprint));
        assert_eq!(ordinal.cardinality(), 1);
    }
}
