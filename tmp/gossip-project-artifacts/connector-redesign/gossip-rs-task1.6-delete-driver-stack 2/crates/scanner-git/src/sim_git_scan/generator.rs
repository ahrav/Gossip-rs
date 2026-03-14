//! Synthetic Git scenario generator for simulation harnesses.
//!
//! The generator builds deterministic repo models suitable for exercising the
//! Git scan pipeline without relying on filesystem state. It favors small,
//! linear histories with predictable tree layouts.
//!
//! Design notes:
//! - Commit history is a single linear chain (each commit has at most one parent).
//! - Tree contents are flat per commit; nested trees are not generated.
//! - Object IDs are deterministic placeholders derived from tags and indices,
//!   not cryptographic hashes.
//! - Randomness is limited to ref tips and optional watermarks and is driven
//!   entirely by the provided seed.

use crate::sim::rng::SimRng;

use super::scenario::{
    GitBlobSpec, GitCommitSpec, GitObjectFormat, GitOid, GitRefSpec, GitRepoModel, GitScenario,
    GitTreeEntryKind, GitTreeEntrySpec, GitTreeSpec, GIT_SCENARIO_SCHEMA_VERSION,
};

/// Configuration for generating synthetic Git scenarios.
#[derive(Clone, Debug)]
pub struct GitScenarioGenConfig {
    /// Scenario schema version to stamp on outputs.
    pub schema_version: u32,
    /// Number of commits to generate in a linear chain.
    pub commit_count: u32,
    /// Number of refs to generate.
    pub ref_count: u32,
    /// Number of blobs per tree.
    pub blobs_per_tree: u32,
}

impl Default for GitScenarioGenConfig {
    fn default() -> Self {
        Self {
            schema_version: GIT_SCENARIO_SCHEMA_VERSION,
            commit_count: 3,
            ref_count: 1,
            blobs_per_tree: 1,
        }
    }
}

impl GitScenarioGenConfig {
    /// Validate that the sizing parameters are non-zero.
    fn validate(&self) -> Result<(), String> {
        if self.commit_count == 0 {
            return Err("commit_count must be > 0".to_string());
        }
        if self.ref_count == 0 {
            return Err("ref_count must be > 0".to_string());
        }
        if self.blobs_per_tree == 0 {
            return Err("blobs_per_tree must be > 0".to_string());
        }
        Ok(())
    }
}

/// Generate a deterministic Git scenario from a seed.
///
/// Returns an error if the configuration is invalid or if the derived blob
/// count overflows `usize`. The resulting scenario has `artifacts = None`.
pub fn generate_scenario(seed: u64, cfg: &GitScenarioGenConfig) -> Result<GitScenario, String> {
    cfg.validate()?;

    let mut rng = SimRng::new(seed);

    let commit_count = cfg.commit_count as usize;
    let blobs_per_tree = cfg.blobs_per_tree as usize;
    let blob_count = commit_count
        .checked_mul(blobs_per_tree)
        .ok_or_else(|| "blob count overflow".to_string())?;

    let mut blobs = Vec::with_capacity(blob_count);
    for idx in 0..blob_count {
        let oid = oid_bytes(0xB0, idx as u32 + 1);
        let bytes = format!("blob_{idx}").into_bytes();
        blobs.push(GitBlobSpec {
            oid: GitOid { bytes: oid },
            bytes,
        });
    }

    let mut trees = Vec::with_capacity(commit_count);
    let mut commits: Vec<GitCommitSpec> = Vec::with_capacity(commit_count);

    for commit_idx in 0..commit_count {
        let tree_oid = oid_bytes(0xA0, commit_idx as u32 + 1);
        let mut entries = Vec::with_capacity(blobs_per_tree);
        for blob_idx in 0..blobs_per_tree {
            let absolute = commit_idx * blobs_per_tree + blob_idx;
            let blob_oid = blobs[absolute].oid.clone();
            let name = format!("file_{commit_idx}_{blob_idx}.txt").into_bytes();
            entries.push(GitTreeEntrySpec {
                name,
                mode: 0o100644,
                oid: blob_oid,
                kind: GitTreeEntryKind::Blob,
            });
        }
        trees.push(GitTreeSpec {
            oid: GitOid {
                bytes: tree_oid.clone(),
            },
            entries,
        });

        let mut parents = Vec::new();
        if commit_idx > 0 {
            let parent_oid = commits[commit_idx - 1].oid.clone();
            parents.push(parent_oid);
        }

        commits.push(GitCommitSpec {
            oid: GitOid {
                bytes: oid_bytes(0xC0, commit_idx as u32 + 1),
            },
            parents,
            tree: GitOid { bytes: tree_oid },
            generation: (commit_idx as u32) + 1,
        });
    }

    let mut refs = Vec::with_capacity(cfg.ref_count as usize);
    for ref_idx in 0..cfg.ref_count {
        let tip_idx = rng.gen_range(0, commit_count as u32) as usize;
        let tip = commits[tip_idx].oid.clone();
        let watermark = if tip_idx > 0 && rng.gen_bool(1, 3) {
            Some(commits[tip_idx - 1].oid.clone())
        } else {
            None
        };

        refs.push(GitRefSpec {
            name: format!("refs/heads/branch_{ref_idx}").into_bytes(),
            tip,
            watermark,
        });
    }

    let repo = GitRepoModel {
        object_format: GitObjectFormat::Sha1,
        refs,
        commits,
        trees,
        blobs,
    };

    Ok(GitScenario {
        schema_version: cfg.schema_version,
        repo,
        artifacts: None,
    })
}

/// Deterministic placeholder OID bytes: `[tag, idx_be, 0, 0, ...]`.
fn oid_bytes(tag: u8, idx: u32) -> Vec<u8> {
    let mut out = vec![0u8; 20];
    out[0] = tag;
    out[1..5].copy_from_slice(&idx.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_deterministic() {
        let cfg = GitScenarioGenConfig::default();
        let a = generate_scenario(42, &cfg).expect("scenario a");
        let b = generate_scenario(42, &cfg).expect("scenario b");
        assert_eq!(a.repo.refs.len(), b.repo.refs.len());
        assert_eq!(a.repo.commits.len(), b.repo.commits.len());
        assert_eq!(a.repo.trees.len(), b.repo.trees.len());
        assert_eq!(a.repo.blobs.len(), b.repo.blobs.len());
        assert_eq!(a.repo.refs[0].name, b.repo.refs[0].name);
        assert_eq!(a.repo.commits[0].oid.bytes, b.repo.commits[0].oid.bytes);
    }
}
