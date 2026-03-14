//! Scenario schema for Git simulation.
//!
//! The schema is intentionally explicit and versioned to support
//! forward-compatible artifact evolution. It models two layers:
//! - A semantic repo model (refs, commits, trees, blobs).
//! - Optional raw artifact bytes (commit-graph, MIDX, packs) for
//!   byte-level simulation cases.
//!
//! Invariants (expected by consumers):
//! - Ref names are raw bytes and must be treated as opaque.
//! - OIDs are stored as raw bytes and must match the repo object format.
//! - Commits should reference existing trees; trees should reference
//!   existing objects. (Not enforced at construction time.)
//! - Blob bytes are immutable for the duration of a run.
//! - OIDs should be unique within each object kind to avoid ambiguity.

use serde::{Deserialize, Serialize};

/// Schema version for `GitScenario` serialization.
pub const GIT_SCENARIO_SCHEMA_VERSION: u32 = 1;

/// Object format used by a simulated repository.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GitObjectFormat {
    /// SHA-1 object IDs (20 bytes).
    #[default]
    Sha1 = 1,
    /// SHA-256 object IDs (32 bytes).
    Sha256 = 2,
}

impl GitObjectFormat {
    /// Returns the byte length for OIDs in this format.
    #[inline]
    #[must_use]
    pub const fn oid_len(self) -> u8 {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

/// Raw object ID bytes (SHA-1 or SHA-256).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GitOid {
    /// Raw OID bytes. Length must match the repo object format.
    pub bytes: Vec<u8>,
}

impl GitOid {
    /// Returns the length of the stored OID in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true when no bytes are present.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Run configuration for a Git simulation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitRunConfig {
    /// Number of simulated worker threads.
    pub workers: u32,
    /// Maximum number of simulation steps (0 = auto-derived).
    pub max_steps: u64,
    /// Number of stability runs with different schedule seeds.
    pub stability_runs: u32,
    /// Trace ring capacity (events retained on failure).
    pub trace_capacity: u32,
}

impl Default for GitRunConfig {
    fn default() -> Self {
        Self {
            workers: 1,
            max_steps: 0,
            stability_runs: 1,
            trace_capacity: 1024,
        }
    }
}

/// Top-level Git simulation scenario.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitScenario {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// Semantic repository model.
    pub repo: GitRepoModel,
    /// Optional embedded artifact bytes for byte-level simulation.
    pub artifacts: Option<GitArtifactBundle>,
}

impl GitScenario {
    /// Returns a new scenario with the current schema version.
    #[must_use]
    pub fn new(repo: GitRepoModel) -> Self {
        Self {
            schema_version: GIT_SCENARIO_SCHEMA_VERSION,
            repo,
            artifacts: None,
        }
    }
}

/// Semantic repository model for simulation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GitRepoModel {
    /// Object ID format (SHA-1 or SHA-256).
    pub object_format: GitObjectFormat,
    /// Refs included in the start set.
    pub refs: Vec<GitRefSpec>,
    /// Commit DAG (referenced by OID).
    pub commits: Vec<GitCommitSpec>,
    /// Tree objects (referenced by OID).
    pub trees: Vec<GitTreeSpec>,
    /// Blob objects (referenced by OID).
    pub blobs: Vec<GitBlobSpec>,
}

/// A ref in the simulated start set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitRefSpec {
    /// Raw ref name bytes (for example `refs/heads/main`).
    pub name: Vec<u8>,
    /// Tip commit OID.
    pub tip: GitOid,
    /// Optional persisted watermark OID (incremental scan).
    pub watermark: Option<GitOid>,
}

/// Commit specification for the semantic model.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitCommitSpec {
    /// Commit OID.
    pub oid: GitOid,
    /// Parent commit OIDs (ordered as in commit object).
    pub parents: Vec<GitOid>,
    /// Root tree OID.
    pub tree: GitOid,
    /// Generation number used for deterministic traversal.
    pub generation: u32,
}

/// Tree specification in the semantic model.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitTreeSpec {
    /// Tree object OID.
    pub oid: GitOid,
    /// Tree entries in Git tree order.
    pub entries: Vec<GitTreeEntrySpec>,
}

/// Tree entry type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GitTreeEntryKind {
    /// Regular blob entry.
    Blob,
    /// Subtree entry.
    Tree,
    /// Gitlink (submodule) entry.
    Commit,
}

/// Tree entry specification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitTreeEntrySpec {
    /// Entry name bytes (not NUL-terminated).
    pub name: Vec<u8>,
    /// Raw mode bits (e.g., 0o100644, 0o040000).
    pub mode: u32,
    /// Target object OID.
    pub oid: GitOid,
    /// Entry kind for disambiguation.
    pub kind: GitTreeEntryKind,
}

/// Blob object specification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitBlobSpec {
    /// Blob OID.
    pub oid: GitOid,
    /// Blob payload bytes.
    pub bytes: Vec<u8>,
}

/// Optional embedded artifact bytes for byte-level simulation.
///
/// When provided, callers should ensure the raw bytes are consistent with the
/// semantic model (object format, referenced pack IDs, and commit graph state).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GitArtifactBundle {
    /// Raw commit-graph bytes (optional).
    pub commit_graph: Option<Vec<u8>>,
    /// Raw multi-pack-index bytes (optional).
    pub midx: Option<Vec<u8>>,
    /// Pack file bytes keyed by pack ID.
    pub packs: Vec<GitPackBytes>,
}

/// Pack bytes for byte-level simulation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GitPackBytes {
    /// Pack ID aligned with MIDX pack order.
    pub pack_id: u16,
    /// Raw pack bytes.
    pub bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_config_defaults_are_stable() {
        let cfg = GitRunConfig::default();
        assert_eq!(cfg.workers, 1);
        assert_eq!(cfg.max_steps, 0);
        assert_eq!(cfg.stability_runs, 1);
        assert_eq!(cfg.trace_capacity, 1024);
    }

    #[test]
    fn scenario_round_trip() {
        let repo = GitRepoModel {
            object_format: GitObjectFormat::Sha1,
            refs: vec![GitRefSpec {
                name: b"refs/heads/main".to_vec(),
                tip: GitOid {
                    bytes: vec![0x11; 20],
                },
                watermark: None,
            }],
            commits: Vec::new(),
            trees: Vec::new(),
            blobs: Vec::new(),
        };
        let scenario = GitScenario::new(repo);
        let json = serde_json::to_string(&scenario).expect("serialize scenario");
        let decoded: GitScenario = serde_json::from_str(&json).expect("deserialize scenario");
        assert_eq!(decoded.schema_version, GIT_SCENARIO_SCHEMA_VERSION);
        assert_eq!(decoded.repo.refs.len(), 1);
    }
}
