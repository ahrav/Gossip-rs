//! Seen-blob store interface for dedupe filtering.
//!
//! Implementations answer batched queries for whether blob OIDs have been
//! scanned before. Callers should provide OIDs in sorted order to improve
//! locality for key-value backends (for example, RocksDB). The API is
//! read-only: it does not mark OIDs as seen.

use std::collections::HashSet;

use super::errors::SpillError;
use super::object_id::OidBytes;

/// Batch query interface for seen-blob filtering.
///
/// # Contract
/// - `batch_check_seen` returns one boolean per input OID.
/// - Output order matches input order.
/// - `true` means the OID has been seen before; `false` means unseen.
/// - Inputs are expected to be sorted for storage locality.
pub trait SeenBlobStore {
    /// Batch query: which OIDs have been seen before?
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError>;
}

/// Seen store that marks all blobs as unseen.
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverSeenStore;

impl SeenBlobStore for NeverSeenStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        Ok(vec![false; oids.len()])
    }
}

/// Seen store that marks all blobs as seen.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysSeenStore;

impl SeenBlobStore for AlwaysSeenStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        Ok(vec![true; oids.len()])
    }
}

/// In-memory seen store for tests and small runs.
///
/// This store grows with every inserted OID and is not persisted.
#[derive(Debug, Default)]
pub struct InMemorySeenStore {
    seen: HashSet<OidBytes>,
}

impl InMemorySeenStore {
    /// Creates an empty in-memory seen store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    /// Inserts an OID into the seen set.
    pub fn insert(&mut self, oid: OidBytes) {
        self.seen.insert(oid);
    }
}

impl SeenBlobStore for InMemorySeenStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        Ok(oids.iter().map(|oid| self.seen.contains(oid)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_seen_store_reports_matches() {
        let mut store = InMemorySeenStore::new();
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);
        let oid_c = OidBytes::sha1([0x33; 20]);

        store.insert(oid_a);
        store.insert(oid_c);

        let flags = store.batch_check_seen(&[oid_a, oid_b, oid_c]).unwrap();

        assert_eq!(flags, vec![true, false, true]);
    }

    #[test]
    fn always_and_never_seen_store_lengths_match() {
        let oids = vec![OidBytes::sha1([0x44; 20]); 3];
        let never = NeverSeenStore;
        let always = AlwaysSeenStore;

        assert_eq!(never.batch_check_seen(&oids).unwrap(), vec![false; 3]);
        assert_eq!(always.batch_check_seen(&oids).unwrap(), vec![true; 3]);
    }
}
