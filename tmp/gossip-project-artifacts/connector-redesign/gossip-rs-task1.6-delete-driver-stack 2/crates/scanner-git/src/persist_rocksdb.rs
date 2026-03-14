//! RocksDB-backed persistence adapters.
//!
//! This module is feature-gated. Enable with `--features rocksdb`.
//! The adapter uses a single RocksDB instance with plain key/value pairs and
//! relies on sorted keys for efficient `multi_get` access.
//! Finalize output is committed with a single `WriteBatch` so data writes and
//! watermarks become visible atomically.
//! When the feature is disabled, public constructors and methods return
//! feature-not-available errors via the appropriate error variant.

use std::io;
use std::path::Path;

use super::errors::{PersistError, RepoOpenError, SpillError};
#[cfg(feature = "rocksdb")]
use super::finalize::build_ref_wm_key;
#[cfg(feature = "rocksdb")]
use super::finalize::FinalizeOutcome;
use super::finalize::FinalizeOutput;
#[cfg(any(feature = "rocksdb", test))]
use super::finalize::NS_SEEN_BLOB;
use super::object_id::OidBytes;
use super::persist::PersistenceStore;
use super::repo_open::RefWatermarkStore;
use super::seen_store::SeenBlobStore;
use super::start_set::StartSetId;
#[cfg(feature = "rocksdb")]
use super::watermark_keys::decode_ref_watermark_value;

#[cfg(feature = "rocksdb")]
use rocksdb::{Options, WriteBatch, DB};

/// RocksDB-backed store for Git scan persistence.
///
/// The store retains the `repo_id` and `policy_hash` used to build
/// `seen_blob` keys for the spill/dedupe stage.
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
}

/// Returns the byte length of a seen-blob key for the given OID length.
#[cfg(any(feature = "rocksdb", test))]
fn seen_blob_key_len(oid_len: u8) -> usize {
    3 + 8 + 32 + oid_len as usize
}

/// Writes a `seen_blob` key into the provided buffer.
///
/// Layout: namespace prefix + repo_id + policy_hash + oid bytes.
#[cfg(any(feature = "rocksdb", test))]
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

impl RocksDbStore {
    /// Opens or creates a RocksDB database at the given path.
    ///
    /// The provided `repo_id` and `policy_hash` are stored on the handle and
    /// used to build keys for `SeenBlobStore` lookups.
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
            })
        }

        #[cfg(not(feature = "rocksdb"))]
        {
            let _ = (path, repo_id, policy_hash);
            Err(PersistError::backend("rocksdb support not enabled"))
        }
    }
}

impl PersistenceStore for RocksDbStore {
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        #[cfg(feature = "rocksdb")]
        {
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
            for op in &output.data_ops {
                batch.put(&op.key, &op.value);
            }
            if matches!(output.outcome, FinalizeOutcome::Complete) {
                for op in &output.watermark_ops {
                    batch.put(&op.key, &op.value);
                }
            }
            self.db
                .write(batch)
                .map_err(|err| PersistError::backend(err.to_string()))?;
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
            // `oids` are expected to be sorted to preserve key ordering.
            // Results mirror the input order because `multi_get` respects the
            // provided key iterator.
            if oids.is_empty() {
                return Ok(Vec::new());
            }

            let oid_len = oids[0].len();
            let key_len = seen_blob_key_len(oid_len);
            // Build a contiguous key buffer so multi_get can borrow slices without per-key Vecs.
            let mut buf = Vec::with_capacity(key_len * oids.len());
            let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(oids.len());
            for oid in oids {
                debug_assert_eq!(oid.len(), oid_len, "mixed oid lengths");
                let start = buf.len();
                let end = start + key_len;
                buf.resize(end, 0);
                write_seen_blob_key(&mut buf[start..end], self.repo_id, &self.policy_hash, oid);
                ranges.push((start, end));
            }
            let keys: Vec<&[u8]> = ranges.iter().map(|(s, e)| &buf[*s..*e]).collect();
            debug_assert!(
                keys.windows(2).all(|w| w[0] <= w[1]),
                "seen keys must be sorted"
            );

            let results = self.db.multi_get(keys.iter());
            let mut out = Vec::with_capacity(results.len());
            for res in results {
                match res {
                    Ok(Some(_)) => out.push(true),
                    Ok(None) => out.push(false),
                    Err(err) => return Err(SpillError::Io(io::Error::other(err.to_string()))),
                }
            }
            Ok(out)
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
    use crate::finalize::build_seen_blob_key;

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
}
