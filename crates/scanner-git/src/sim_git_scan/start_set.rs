//! Start set adapters for Git simulation.
//!
//! These adapters bridge the simulation repo model into the `StartSetResolver`
//! and `RefWatermarkStore` traits used by `repo_open`.

use std::collections::HashMap;
use std::num::NonZeroU32;

use crate::watermark_keys::RefWatermark;
use crate::StartSetId;
use crate::{ObjectFormat, OidBytes};
use crate::{RefWatermarkStore, RepoOpenError, StartSetResolver};

use super::convert::{to_object_format, to_oid_bytes};
use super::error::SimGitError;
use super::scenario::{GitRefSpec, GitRepoModel};

/// Simulated start set based on the repo model.
///
/// The start set preserves the ref list from the model; ordering and size
/// constraints are enforced by `repo_open` when it calls the resolver.
#[derive(Debug)]
pub struct SimStartSet {
    object_format: ObjectFormat,
    refs: Vec<SimRef>,
}

#[derive(Clone, Debug)]
struct SimRef {
    name: Vec<u8>,
    tip: OidBytes,
    watermark: Option<RefWatermark>,
}

impl SimStartSet {
    /// Build a simulated start set from the repo model.
    ///
    /// This performs OID length validation but does not check for duplicate
    /// ref names; duplicates will share a watermark entry.
    pub fn from_repo(repo: &GitRepoModel) -> Result<Self, SimGitError> {
        let object_format = to_object_format(repo.object_format);
        let mut generations = HashMap::with_capacity(repo.commits.len());
        for commit in &repo.commits {
            let oid = to_oid_bytes(&commit.oid, object_format)?;
            generations.insert(oid, commit.generation);
        }
        let mut refs = Vec::with_capacity(repo.refs.len());
        for r in &repo.refs {
            refs.push(convert_ref(r, object_format, &generations)?);
        }
        Ok(Self {
            object_format,
            refs,
        })
    }

    /// Returns the object format used by the start set.
    #[must_use]
    pub const fn object_format(&self) -> ObjectFormat {
        self.object_format
    }

    /// Build a ref-name-to-watermark map for fast lookup.
    ///
    /// If duplicate ref names exist, the last one wins.
    fn watermark_map(&self) -> HashMap<Vec<u8>, Option<RefWatermark>> {
        let mut map = HashMap::with_capacity(self.refs.len());
        for r in &self.refs {
            map.insert(r.name.clone(), r.watermark);
        }
        map
    }
}

fn convert_ref(
    r: &GitRefSpec,
    format: ObjectFormat,
    generations: &HashMap<OidBytes, u32>,
) -> Result<SimRef, SimGitError> {
    Ok(SimRef {
        name: r.name.clone(),
        tip: to_oid_bytes(&r.tip, format)?,
        watermark: match &r.watermark {
            Some(oid) => {
                let oid = to_oid_bytes(oid, format)?;
                let generation =
                    generations
                        .get(&oid)
                        .copied()
                        .ok_or(SimGitError::MissingObject {
                            kind: "watermark commit",
                        })?;
                let gen = NonZeroU32::new(generation)
                    .ok_or(SimGitError::InvalidGeneration { generation })?;
                Some(RefWatermark {
                    oid,
                    generation: gen,
                })
            }
            None => None,
        },
    })
}

impl StartSetResolver for SimStartSet {
    fn resolve(
        &self,
        _paths: &crate::GitRepoPaths,
    ) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        Ok(self.refs.iter().map(|r| (r.name.clone(), r.tip)).collect())
    }
}

impl RefWatermarkStore for SimStartSet {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: StartSetId,
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<RefWatermark>>, RepoOpenError> {
        let map = self.watermark_map();
        let mut out = Vec::with_capacity(ref_names.len());
        for name in ref_names {
            out.push(map.get(*name).copied().flatten());
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(val: u8) -> Vec<u8> {
        vec![val; 20]
    }

    #[test]
    fn start_set_converts_refs() {
        let repo = GitRepoModel {
            object_format: super::super::scenario::GitObjectFormat::Sha1,
            refs: vec![GitRefSpec {
                name: b"refs/heads/main".to_vec(),
                tip: super::super::scenario::GitOid { bytes: oid(1) },
                watermark: Some(super::super::scenario::GitOid { bytes: oid(2) }),
            }],
            commits: vec![super::super::scenario::GitCommitSpec {
                oid: super::super::scenario::GitOid { bytes: oid(2) },
                parents: Vec::new(),
                tree: super::super::scenario::GitOid { bytes: oid(99) },
                generation: 1,
            }],
            trees: Vec::new(),
            blobs: Vec::new(),
        };

        let start_set = SimStartSet::from_repo(&repo).expect("start set");
        assert_eq!(start_set.refs.len(), 1);
    }
}
