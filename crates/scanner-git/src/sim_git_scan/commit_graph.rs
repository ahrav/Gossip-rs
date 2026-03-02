//! Simulated commit-graph adapter for Git simulation.
//!
//! Provides a deterministic, in-memory `CommitGraph` implementation built
//! from the `GitRepoModel`. This allows commit walk logic to be exercised
//! without on-disk commit-graph files.
//!
//! # Model assumptions
//! - `repo.commits` defines the commit position order (index -> `Position`).
//! - Parent OIDs must exist in `repo.commits`; missing parents are errors.
//! - Generation numbers are trusted as provided (no recomputation).

use std::collections::HashMap;

use gix_commitgraph::Position;

use crate::{CommitGraph, CommitPlanError, OidBytes, ParentScratch};

use super::convert::{to_object_format, to_oid_bytes};
use super::error::SimGitError;
use super::scenario::{GitCommitSpec, GitRepoModel};

/// Simulated commit-graph backed by the Git repo model.
#[derive(Debug)]
pub struct SimCommitGraph {
    object_format: crate::ObjectFormat,
    generations: Vec<u32>,
    parents: Vec<Vec<Position>>,
    roots: Vec<OidBytes>,
    oid_to_pos: HashMap<OidBytes, Position>,
}

impl SimCommitGraph {
    /// Build a simulated commit-graph from a repo model.
    ///
    /// This assigns positions in `repo.commits` order and precomputes parent
    /// links to avoid repeated OID lookups during walks.
    ///
    /// # Errors
    /// - `InvalidOidLength` if any commit, tree, or parent OID length is wrong.
    /// - `DuplicateOid` if two commits share the same OID.
    /// - `MissingObject` if a parent OID is not present in the model.
    pub fn from_repo(repo: &GitRepoModel) -> Result<Self, SimGitError> {
        let object_format = to_object_format(repo.object_format);
        let mut oid_to_pos = HashMap::with_capacity(repo.commits.len());
        let mut roots = Vec::with_capacity(repo.commits.len());
        let mut generations = Vec::with_capacity(repo.commits.len());

        for (idx, commit) in repo.commits.iter().enumerate() {
            let oid = to_oid_bytes(&commit.oid, object_format)?;
            if oid_to_pos.insert(oid, Position(idx as u32)).is_some() {
                return Err(SimGitError::DuplicateOid { kind: "commit" });
            }
            roots.push(to_oid_bytes(&commit.tree, object_format)?);
            generations.push(commit.generation);
        }

        let mut parents = Vec::with_capacity(repo.commits.len());
        for commit in &repo.commits {
            parents.push(resolve_parents(object_format, &oid_to_pos, commit)?);
        }

        Ok(Self {
            object_format,
            generations,
            parents,
            roots,
            oid_to_pos,
        })
    }

    /// Returns the root tree OID for the commit at `pos`.
    ///
    /// Returns `MissingObject` if `pos` is out of range.
    pub fn root_tree_oid(&self, pos: Position) -> Result<OidBytes, SimGitError> {
        let idx = pos.0 as usize;
        if idx >= self.roots.len() {
            return Err(SimGitError::MissingObject { kind: "commit" });
        }
        Ok(self.roots[idx])
    }

    /// Returns parent positions for a commit.
    #[must_use]
    pub fn parents(&self, pos: Position) -> &[Position] {
        let idx = pos.0 as usize;
        self.parents
            .get(idx)
            .map(|p| p.as_slice())
            .unwrap_or_default()
    }
}

/// Resolve parent positions for a commit spec.
///
/// Returns `MissingObject` if any parent OID is not present in the model.
fn resolve_parents(
    format: crate::ObjectFormat,
    oid_to_pos: &HashMap<OidBytes, Position>,
    commit: &GitCommitSpec,
) -> Result<Vec<Position>, SimGitError> {
    let mut out = Vec::with_capacity(commit.parents.len());
    for parent in &commit.parents {
        let oid = to_oid_bytes(parent, format)?;
        let pos = oid_to_pos
            .get(&oid)
            .copied()
            .ok_or(SimGitError::MissingObject { kind: "parent" })?;
        out.push(pos);
    }
    Ok(out)
}

impl CommitGraph for SimCommitGraph {
    fn num_commits(&self) -> u32 {
        self.parents.len() as u32
    }

    fn lookup(&self, oid: &OidBytes) -> Result<Option<Position>, CommitPlanError> {
        let expected = self.object_format.oid_len() as usize;
        let len = oid.len() as usize;
        if len != expected {
            return Err(CommitPlanError::InvalidOidLength { len, expected });
        }
        Ok(self.oid_to_pos.get(oid).copied())
    }

    fn generation(&self, pos: Position) -> u32 {
        self.generations[pos.0 as usize]
    }

    fn collect_parents(
        &self,
        pos: Position,
        max_parents: u32,
        scratch: &mut ParentScratch,
    ) -> Result<(), CommitPlanError> {
        scratch.clear();
        let idx = pos.0 as usize;
        if idx >= self.parents.len() {
            return Err(CommitPlanError::ParentDecodeFailed);
        }
        for &p in &self.parents[idx] {
            scratch.push(p, max_parents)?;
        }
        Ok(())
    }

    fn root_tree_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
        let idx = pos.0 as usize;
        if idx >= self.roots.len() {
            return Err(CommitPlanError::ParentDecodeFailed);
        }
        Ok(self.roots[idx])
    }

    /// Reverse-lookup: finds the OID for a given position by linear scan.
    ///
    /// O(n) because the primary map is OID-to-position. Acceptable for
    /// simulation workloads.
    fn commit_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
        for (oid, &p) in &self.oid_to_pos {
            if p == pos {
                return Ok(*oid);
            }
        }
        Err(CommitPlanError::ParentDecodeFailed)
    }

    /// Returns 0 for all positions; the simulation harness does not model timestamps.
    fn committer_timestamp(&self, _pos: Position) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ByteArena, OidBytes};
    use crate::{CommitPlanIter, CommitWalkLimits, StartSetRef};

    fn oid(val: u8) -> Vec<u8> {
        vec![val; 20]
    }

    #[test]
    fn force_push_watermark_scans_full_history() {
        let repo = GitRepoModel {
            object_format: super::super::scenario::GitObjectFormat::Sha1,
            refs: Vec::new(),
            commits: vec![
                GitCommitSpec {
                    oid: super::super::scenario::GitOid { bytes: oid(1) },
                    parents: Vec::new(),
                    tree: super::super::scenario::GitOid { bytes: oid(10) },
                    generation: 1,
                },
                GitCommitSpec {
                    oid: super::super::scenario::GitOid { bytes: oid(2) },
                    parents: vec![super::super::scenario::GitOid { bytes: oid(1) }],
                    tree: super::super::scenario::GitOid { bytes: oid(11) },
                    generation: 2,
                },
                GitCommitSpec {
                    oid: super::super::scenario::GitOid { bytes: oid(3) },
                    parents: vec![super::super::scenario::GitOid { bytes: oid(2) }],
                    tree: super::super::scenario::GitOid { bytes: oid(12) },
                    generation: 3,
                },
                // unrelated commit used as watermark (force-push case)
                GitCommitSpec {
                    oid: super::super::scenario::GitOid { bytes: oid(9) },
                    parents: Vec::new(),
                    tree: super::super::scenario::GitOid { bytes: oid(13) },
                    generation: 1,
                },
            ],
            trees: Vec::new(),
            blobs: Vec::new(),
        };

        let sim = SimCommitGraph::from_repo(&repo).expect("sim graph");

        let mut arena = ByteArena::with_capacity(128);
        let name = arena.intern(b"refs/heads/main").expect("ref name");
        let tip = OidBytes::from_slice(&oid(3));
        let watermark = Some(OidBytes::from_slice(&oid(9)));
        let refs = vec![StartSetRef {
            name,
            tip,
            watermark,
        }];

        let limits = CommitWalkLimits::default();
        let plan = CommitPlanIter::new_from_refs(&refs, &sim, limits).expect("plan");
        let commits: Vec<_> = plan.collect::<Result<Vec<_>, _>>().expect("collect");

        assert_eq!(commits.len(), 3, "should scan full history from tip");
    }
}
