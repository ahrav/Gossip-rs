//! Deterministic minimizer for Git simulation artifacts.
//!
//! This module shrinks a failing [`GitReproArtifact`] using a fixed set of
//! removal-only passes. Each candidate is validated with a caller-provided
//! `reproduce` predicate; only candidates that still reproduce the failure are
//! kept.
//!
//! Invariants and expectations:
//! - The minimizer only removes data; it never mutates the content of retained
//!   objects (aside from truncating read sequences in the fault plan).
//! - Pass order and iteration are deterministic, so identical inputs and a
//!   deterministic `reproduce` predicate yield identical outputs.
//! - The output is locally minimal with respect to the enabled passes, but is
//!   not guaranteed to be globally minimal.
//! - If the repository graph contains dangling refs/parents/trees, the
//!   reachability pruning pass is skipped to avoid hiding inconsistent input.

use super::artifact::GitReproArtifact;
use super::fault::GitResourceId;
use super::scenario::{GitRepoModel, GitTreeEntryKind};

use std::collections::{HashMap, HashSet};

/// Configuration for deterministic minimization.
#[derive(Clone, Copy, Debug)]
pub struct MinimizerCfg {
    /// Maximum full-pass iterations (prevents non-terminating shrink loops).
    pub max_iterations: u32,
}

impl Default for MinimizerCfg {
    fn default() -> Self {
        Self { max_iterations: 8 }
    }
}

/// Minimize a failing Git simulation case.
///
/// The `reproduce` callback should return true only when the failure still
/// reproduces under the candidate artifact. It must be deterministic and
/// side-effect free because it is called repeatedly on cloned candidates.
pub fn minimize_git_case(
    failing: &GitReproArtifact,
    cfg: MinimizerCfg,
    reproduce: impl Fn(&GitReproArtifact) -> bool,
) -> GitReproArtifact {
    let mut current = failing.clone();
    for _ in 0..cfg.max_iterations {
        // Iterate until a full pass yields no change; earlier removals can make
        // later passes effective, so we loop a bounded number of times.
        let mut changed = false;
        changed |= shrink_fault_plan(&mut current, &reproduce);
        changed |= shrink_refs(&mut current, &reproduce);
        changed |= prune_unreachable_objects(&mut current, &reproduce);
        changed |= reduce_artifacts(&mut current, &reproduce);
        if !changed {
            break;
        }
    }
    current
}

fn shrink_fault_plan(
    artifact: &mut GitReproArtifact,
    reproduce: &impl Fn(&GitReproArtifact) -> bool,
) -> bool {
    let mut changed = false;

    // Drop whole resources (reverse order to keep deterministic indices).
    let mut idx = artifact.fault_plan.resources.len();
    while idx > 0 {
        idx -= 1;
        let mut candidate = artifact.clone();
        candidate.fault_plan.resources.remove(idx);
        if reproduce(&candidate) {
            *artifact = candidate;
            changed = true;
        }
    }

    // Trim read sequences per resource.
    for res_idx in 0..artifact.fault_plan.resources.len() {
        loop {
            let reads_len = artifact.fault_plan.resources[res_idx].reads.len();
            if reads_len == 0 {
                break;
            }
            let mut candidate = artifact.clone();
            candidate.fault_plan.resources[res_idx]
                .reads
                .truncate(reads_len - 1);
            if reproduce(&candidate) {
                *artifact = candidate;
                changed = true;
            } else {
                break;
            }
        }
    }

    // Remove empty resources to keep the plan compact (Other(...) resources
    // are retained regardless to preserve non-read fault injection).
    let mut candidate = artifact.clone();
    candidate
        .fault_plan
        .resources
        .retain(|r| !r.reads.is_empty() || matches!(r.resource, GitResourceId::Other(_)));
    if candidate.fault_plan.resources.len() != artifact.fault_plan.resources.len()
        && reproduce(&candidate)
    {
        *artifact = candidate;
        changed = true;
    }

    changed
}

fn shrink_refs(
    artifact: &mut GitReproArtifact,
    reproduce: &impl Fn(&GitReproArtifact) -> bool,
) -> bool {
    let mut changed = false;
    let refs_len = artifact.scenario.repo.refs.len();
    if refs_len <= 1 {
        return false;
    }

    // Keep the first ref stable to avoid shifting the remaining entries.
    let mut idx = refs_len;
    while idx > 1 {
        idx -= 1;
        let mut candidate = artifact.clone();
        candidate.scenario.repo.refs.remove(idx);
        if reproduce(&candidate) {
            *artifact = candidate;
            changed = true;
        }
    }
    changed
}

fn prune_unreachable_objects(
    artifact: &mut GitReproArtifact,
    reproduce: &impl Fn(&GitReproArtifact) -> bool,
) -> bool {
    let repo = &artifact.scenario.repo;
    let Some(pruned) = prune_repo(repo) else {
        // The repo contains dangling references; avoid masking the inconsistency.
        return false;
    };
    if pruned.commits.len() == repo.commits.len()
        && pruned.trees.len() == repo.trees.len()
        && pruned.blobs.len() == repo.blobs.len()
    {
        return false;
    }

    let mut candidate = artifact.clone();
    candidate.scenario.repo = pruned;
    if reproduce(&candidate) {
        *artifact = candidate;
        return true;
    }
    false
}

fn reduce_artifacts(
    artifact: &mut GitReproArtifact,
    reproduce: &impl Fn(&GitReproArtifact) -> bool,
) -> bool {
    if artifact.scenario.artifacts.is_none() {
        return false;
    }
    let mut candidate = artifact.clone();
    candidate.scenario.artifacts = None;
    if reproduce(&candidate) {
        *artifact = candidate;
        return true;
    }
    false
}

/// Keep only objects reachable from refs; return `None` if the input graph is inconsistent.
fn prune_repo(repo: &GitRepoModel) -> Option<GitRepoModel> {
    let mut commit_map: HashMap<&[u8], usize> = HashMap::new();
    for (idx, commit) in repo.commits.iter().enumerate() {
        commit_map.insert(commit.oid.bytes.as_slice(), idx);
    }

    let mut keep_commits = HashSet::new();
    let mut stack = Vec::new();
    for r in &repo.refs {
        let &idx = commit_map.get(r.tip.bytes.as_slice())?;
        stack.push(idx);
    }

    // DFS from ref tips through parents to find reachable commits.
    while let Some(idx) = stack.pop() {
        if !keep_commits.insert(idx) {
            continue;
        }
        for parent in &repo.commits[idx].parents {
            let &pidx = commit_map.get(parent.bytes.as_slice())?;
            stack.push(pidx);
        }
    }

    let mut commits = Vec::new();
    for (idx, commit) in repo.commits.iter().enumerate() {
        if keep_commits.contains(&idx) {
            commits.push(commit.clone());
        }
    }

    let mut tree_map: HashMap<&[u8], usize> = HashMap::new();
    for (idx, tree) in repo.trees.iter().enumerate() {
        tree_map.insert(tree.oid.bytes.as_slice(), idx);
    }

    let mut keep_trees = HashSet::new();
    let mut tree_stack = Vec::new();
    for commit in &commits {
        let &idx = tree_map.get(commit.tree.bytes.as_slice())?;
        tree_stack.push(idx);
    }

    // DFS over tree entries to retain reachable trees and collect blob OIDs.
    while let Some(idx) = tree_stack.pop() {
        if !keep_trees.insert(idx) {
            continue;
        }
        for entry in &repo.trees[idx].entries {
            if entry.kind != GitTreeEntryKind::Tree {
                continue;
            }
            let &tidx = tree_map.get(entry.oid.bytes.as_slice())?;
            tree_stack.push(tidx);
        }
    }

    let mut trees = Vec::new();
    let mut blob_oids = HashSet::new();
    for (idx, tree) in repo.trees.iter().enumerate() {
        if keep_trees.contains(&idx) {
            for entry in &tree.entries {
                if entry.kind == GitTreeEntryKind::Blob {
                    blob_oids.insert(entry.oid.bytes.as_slice().to_vec());
                }
            }
            trees.push(tree.clone());
        }
    }

    let mut blobs = Vec::new();
    for blob in &repo.blobs {
        if blob_oids.contains(blob.oid.bytes.as_slice()) {
            blobs.push(blob.clone());
        }
    }

    Some(GitRepoModel {
        object_format: repo.object_format,
        refs: repo.refs.clone(),
        commits,
        trees,
        blobs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_git_scan::artifact::{GitReproArtifact, GitTraceDump};
    use crate::sim_git_scan::fault::GitFaultPlan;
    use crate::sim_git_scan::runner::{FailureKind, FailureReport};
    use crate::sim_git_scan::scenario::{
        GitBlobSpec, GitCommitSpec, GitObjectFormat, GitOid, GitRefSpec, GitRepoModel, GitScenario,
        GitTreeEntryKind, GitTreeEntrySpec, GitTreeSpec,
    };

    fn oid(val: u8) -> GitOid {
        GitOid {
            bytes: vec![val; 20],
        }
    }

    fn base_artifact() -> GitReproArtifact {
        GitReproArtifact {
            schema_version: 1,
            scanner_pkg_version: "dev".to_string(),
            git_commit: None,
            target: "local".to_string(),
            scenario_seed: 1,
            schedule_seed: 1,
            run_config: crate::sim_git_scan::GitRunConfig::default(),
            scenario: GitScenario {
                schema_version: 1,
                repo: GitRepoModel {
                    object_format: GitObjectFormat::Sha1,
                    refs: Vec::new(),
                    commits: Vec::new(),
                    trees: Vec::new(),
                    blobs: Vec::new(),
                },
                artifacts: None,
            },
            fault_plan: GitFaultPlan::default(),
            failure: FailureReport {
                kind: FailureKind::OracleMismatch,
                message: "x".to_string(),
                step: 0,
            },
            trace: GitTraceDump {
                ring: Vec::new(),
                full: None,
            },
        }
    }

    #[test]
    fn minimizer_drops_extra_refs() {
        let mut artifact = base_artifact();
        artifact.scenario.repo.refs = vec![
            GitRefSpec {
                name: b"refs/heads/main".to_vec(),
                tip: oid(1),
                watermark: None,
            },
            GitRefSpec {
                name: b"refs/heads/extra".to_vec(),
                tip: oid(1),
                watermark: None,
            },
        ];

        let minimized = minimize_git_case(&artifact, MinimizerCfg::default(), |_| true);
        assert_eq!(minimized.scenario.repo.refs.len(), 1);
    }

    #[test]
    fn minimizer_prunes_unreachable_commits() {
        let mut artifact = base_artifact();
        artifact.scenario.repo.refs = vec![GitRefSpec {
            name: b"refs/heads/main".to_vec(),
            tip: oid(1),
            watermark: None,
        }];
        artifact.scenario.repo.commits = vec![
            GitCommitSpec {
                oid: oid(1),
                parents: Vec::new(),
                tree: oid(2),
                generation: 1,
            },
            GitCommitSpec {
                oid: oid(9),
                parents: Vec::new(),
                tree: oid(3),
                generation: 1,
            },
        ];
        artifact.scenario.repo.trees = vec![
            GitTreeSpec {
                oid: oid(2),
                entries: vec![GitTreeEntrySpec {
                    name: b"file.txt".to_vec(),
                    mode: 0o100644,
                    oid: oid(4),
                    kind: GitTreeEntryKind::Blob,
                }],
            },
            GitTreeSpec {
                oid: oid(3),
                entries: Vec::new(),
            },
        ];
        artifact.scenario.repo.blobs = vec![GitBlobSpec {
            oid: oid(4),
            bytes: b"hello".to_vec(),
        }];

        let minimized = minimize_git_case(&artifact, MinimizerCfg::default(), |_| true);
        assert_eq!(minimized.scenario.repo.commits.len(), 1);
        assert_eq!(minimized.scenario.repo.trees.len(), 1);
    }

    #[test]
    fn minimizer_drops_artifacts() {
        let mut artifact = base_artifact();
        artifact.scenario.artifacts = Some(crate::sim_git_scan::scenario::GitArtifactBundle {
            commit_graph: None,
            midx: None,
            packs: vec![
                crate::sim_git_scan::scenario::GitPackBytes {
                    pack_id: 0,
                    bytes: vec![1, 2, 3],
                },
                crate::sim_git_scan::scenario::GitPackBytes {
                    pack_id: 1,
                    bytes: vec![4, 5, 6],
                },
            ],
        });

        let minimized = minimize_git_case(&artifact, MinimizerCfg::default(), |_| true);
        assert!(minimized.scenario.artifacts.is_none());
    }
}
