//! Tree source adapter for Git simulation.
//!
//! Encodes semantic tree specs into raw Git tree bytes and provides a
//! `TreeSource` implementation for tree diffing.
//!
//! # Encoding notes
//! Entries are serialized as `<mode> <name>\\0<oid-bytes>` in the order
//! provided by the scenario. The encoder does not sort entries; callers
//! should supply Git tree order to mirror real trees.

use std::collections::{HashMap, HashSet};

use crate::{ObjectFormat, OidBytes, TreeBytes, TreeDiffError, TreeSource};

use super::convert::{to_object_format, to_oid_bytes};
use super::error::SimGitError;
use super::scenario::{GitRepoModel, GitTreeEntrySpec, GitTreeSpec};

/// Simulated tree source backed by the repo model.
///
/// The tree payloads are pre-encoded for deterministic access during tree
/// diffing. Each `load_tree` call clones the cached bytes into an owned
/// `TreeBytes`.
#[derive(Debug)]
pub struct SimTreeSource {
    oid_len: u8,
    trees: HashMap<OidBytes, Vec<u8>>,
    blobs: HashSet<OidBytes>,
}

impl SimTreeSource {
    /// Build a simulated tree source from the repo model.
    ///
    /// Returns `DuplicateOid` if two trees share an OID. Blob OIDs are
    /// collected only to disambiguate `NotATree` vs missing objects.
    pub fn from_repo(repo: &GitRepoModel) -> Result<Self, SimGitError> {
        let format = to_object_format(repo.object_format);
        let oid_len = format.oid_len();

        let mut trees = HashMap::with_capacity(repo.trees.len());
        for tree in &repo.trees {
            let oid = to_oid_bytes(&tree.oid, format)?;
            if trees.contains_key(&oid) {
                return Err(SimGitError::DuplicateOid { kind: "tree" });
            }
            let bytes = encode_tree(tree, format)?;
            trees.insert(oid, bytes);
        }

        let mut blobs = HashSet::with_capacity(repo.blobs.len());
        for blob in &repo.blobs {
            let oid = to_oid_bytes(&blob.oid, format)?;
            blobs.insert(oid);
        }

        Ok(Self {
            oid_len,
            trees,
            blobs,
        })
    }
}

impl TreeSource for SimTreeSource {
    fn load_tree(&mut self, oid: &OidBytes) -> Result<TreeBytes, TreeDiffError> {
        if oid.len() != self.oid_len {
            return Err(TreeDiffError::InvalidOidLength {
                len: oid.len() as usize,
                expected: self.oid_len as usize,
            });
        }

        if let Some(bytes) = self.trees.get(oid) {
            return Ok(TreeBytes::Owned(bytes.clone()));
        }

        if self.blobs.contains(oid) {
            return Err(TreeDiffError::NotATree);
        }

        Err(TreeDiffError::TreeNotFound)
    }
}

/// Encode a tree spec into raw Git tree bytes.
///
/// Callers must supply entries in Git tree order; this function does not sort.
fn encode_tree(tree: &GitTreeSpec, format: ObjectFormat) -> Result<Vec<u8>, SimGitError> {
    let mut out = Vec::new();
    for entry in &tree.entries {
        encode_entry(&mut out, entry, format)?;
    }
    Ok(out)
}

/// Encode a single tree entry.
///
/// The entry kind is not validated here; the `mode` is serialized verbatim.
fn encode_entry(
    out: &mut Vec<u8>,
    entry: &GitTreeEntrySpec,
    format: ObjectFormat,
) -> Result<(), SimGitError> {
    let mode = format!("{:o}", entry.mode);
    out.extend_from_slice(mode.as_bytes());
    out.push(b' ');
    out.extend_from_slice(&entry.name);
    out.push(0);
    let oid = to_oid_bytes(&entry.oid, format)?;
    out.extend_from_slice(oid.as_slice());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CandidateBuffer, ChangeKind, TreeDiffLimits, TreeDiffWalker};
    use std::sync::atomic::AtomicBool;

    fn oid(val: u8) -> Vec<u8> {
        vec![val; 20]
    }

    #[test]
    fn gitlink_entries_are_skipped() {
        let repo = GitRepoModel {
            object_format: super::super::scenario::GitObjectFormat::Sha1,
            refs: Vec::new(),
            commits: Vec::new(),
            trees: vec![GitTreeSpec {
                oid: super::super::scenario::GitOid { bytes: oid(1) },
                entries: vec![
                    GitTreeEntrySpec {
                        name: b"blob.txt".to_vec(),
                        mode: 0o100644,
                        oid: super::super::scenario::GitOid { bytes: oid(2) },
                        kind: super::super::scenario::GitTreeEntryKind::Blob,
                    },
                    GitTreeEntrySpec {
                        name: b"submodule".to_vec(),
                        mode: 0o160000,
                        oid: super::super::scenario::GitOid { bytes: oid(3) },
                        kind: super::super::scenario::GitTreeEntryKind::Commit,
                    },
                ],
            }],
            blobs: vec![super::super::scenario::GitBlobSpec {
                oid: super::super::scenario::GitOid { bytes: oid(2) },
                bytes: b"hello".to_vec(),
            }],
        };

        let mut source = SimTreeSource::from_repo(&repo).expect("tree source");
        let limits = TreeDiffLimits::default();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut out = CandidateBuffer::new(&limits, 20);
        let abort = AtomicBool::new(false);

        let tree_oid = OidBytes::from_slice(&oid(1));
        walker
            .diff_trees(&mut source, &mut out, Some(&tree_oid), None, 1, 0, &abort)
            .expect("diff");

        let candidates: Vec<_> = out.iter_resolved().collect();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].change_kind, ChangeKind::Add);
    }
}
