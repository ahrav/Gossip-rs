//! Design-doc-audit pipeline.
//!
//! File discovery, scope-map parsing, state-based filtering, round-robin
//! partitioning, runbook template substitution, and state-update helpers for
//! the design-doc-audit fleet pipeline.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::config::AuditConfig;
use crate::state::AuditFileState;

// ---------------------------------------------------------------------------
// Scope-map parsing
// ---------------------------------------------------------------------------

/// A single entry from `docs/scope-map.toml`.
#[derive(Debug, Clone)]
pub struct ScopeEntry {
    pub doc: String,
    pub dir: String,
}

/// Deserialization target for the scope-map TOML file.
#[derive(Deserialize)]
struct ScopeMapFile {
    #[serde(default)]
    scopes: Vec<ScopeEntryRaw>,
}

#[derive(Deserialize)]
struct ScopeEntryRaw {
    doc: String,
    dir: String,
}

/// Parse `docs/scope-map.toml` and return the list of scope entries.
pub fn parse_scope_map(path: &Path) -> anyhow::Result<Vec<ScopeEntry>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;

    let parsed: ScopeMapFile =
        toml::from_str(&content).with_context(|| format!("parse TOML from {}", path.display()))?;

    Ok(parsed
        .scopes
        .into_iter()
        .map(|e| ScopeEntry {
            doc: e.doc,
            dir: e.dir,
        })
        .collect())
}

/// Look up the source directories associated with a document file.
///
/// A document may appear in multiple `[[scopes]]` entries; this returns the
/// deduplicated union of all matching `dir` values.
pub fn doc_source_dirs(doc_path: &str, scope_entries: &[ScopeEntry]) -> Vec<String> {
    let mut dirs: Vec<String> = scope_entries
        .iter()
        .filter(|e| e.doc == doc_path)
        .map(|e| e.dir.clone())
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

/// Classification of a discovered documentation file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileKind {
    Doc,
    Diagram,
}

/// A candidate documentation or diagram file for auditing.
#[derive(Debug, Clone)]
pub struct CandidateFile {
    pub kind: FileKind,
    pub path: String,
}

/// Walk `docs/` and `diagrams/` for `.md` files, skipping `findings/`
/// subdirectories. Returns candidates sorted by path for determinism.
pub fn discover_files() -> anyhow::Result<Vec<CandidateFile>> {
    let mut candidates = Vec::new();

    // Walk docs/.
    if Path::new("docs").is_dir() {
        walk_md_files("docs", FileKind::Doc, &mut candidates)?;
    }

    // Walk diagrams/.
    if Path::new("diagrams").is_dir() {
        walk_md_files("diagrams", FileKind::Diagram, &mut candidates)?;
    }

    candidates.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(candidates)
}

/// Recursively collect `.md` files under `root`, skipping `findings/` dirs.
fn walk_md_files(root: &str, kind: FileKind, out: &mut Vec<CandidateFile>) -> anyhow::Result<()> {
    for entry in walkdir(root)? {
        let path = entry;

        // Skip findings subdirectories (matches bash script's logic).
        if path.contains("findings") {
            continue;
        }

        if path.ends_with(".md") {
            out.push(CandidateFile {
                kind: kind.clone(),
                path,
            });
        }
    }

    Ok(())
}

/// Simple recursive directory walk that returns repo-relative paths.
fn walkdir(root: &str) -> anyhow::Result<Vec<String>> {
    let mut result = Vec::new();
    walkdir_inner(Path::new(root), &mut result)?;
    Ok(result)
}

fn walkdir_inner(dir: &Path, out: &mut Vec<String>) -> anyhow::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("read dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .collect();

    // Sort for determinism.
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            walkdir_inner(&path, out)?;
        } else if path.is_file() {
            // Convert to repo-relative path string.
            if let Some(s) = path.to_str() {
                out.push(s.to_owned());
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// State-based filtering
// ---------------------------------------------------------------------------

/// Filter out candidate files whose blob SHA has not changed since the last
/// audit. Returns the files to process and the count of skipped files.
pub fn filter_unchanged(
    candidates: Vec<CandidateFile>,
    current_blobs: &HashMap<String, String>,
    audit_state: &HashMap<String, AuditFileState>,
    full_mode: bool,
) -> (Vec<CandidateFile>, usize) {
    if full_mode {
        return (candidates, 0);
    }

    let mut to_process = Vec::new();
    let mut skipped = 0usize;

    for file in candidates {
        let blob = current_blobs.get(&file.path).map(String::as_str);
        let stored = audit_state.get(&file.path);

        let unchanged = match (blob, stored) {
            (Some(current), Some(state)) if !current.is_empty() => current == state.blob_sha,
            _ => false,
        };

        if unchanged {
            skipped += 1;
        } else {
            to_process.push(file);
        }
    }

    (to_process, skipped)
}

// ---------------------------------------------------------------------------
// Blob SHA reader for docs/diagrams
// ---------------------------------------------------------------------------

/// Get current blob SHAs for all files under `docs/` and `diagrams/` via
/// `git ls-tree`. Returns a map from file path (repo-relative) to blob SHA.
pub fn get_doc_blobs(ref_spec: &str) -> anyhow::Result<HashMap<String, String>> {
    let mut blobs = HashMap::new();

    for prefix in &["docs/", "diagrams/"] {
        let output = Command::new("git")
            .args(["ls-tree", "-r", ref_spec, "--", prefix])
            .output()
            .with_context(|| format!("git ls-tree for {prefix}"))?;

        if !output.status.success() {
            // The prefix might not exist (e.g. no diagrams/ directory).
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let (meta, path) = match line.split_once('\t') {
                Some(pair) => pair,
                None => continue,
            };
            let sha = meta.split_whitespace().nth(2).unwrap_or("");
            if !sha.is_empty() {
                blobs.insert(path.to_owned(), sha.to_owned());
            }
        }
    }

    Ok(blobs)
}

// ---------------------------------------------------------------------------
// Audit manifest and partitioning
// ---------------------------------------------------------------------------

/// Per-agent work assignment for the audit pipeline.
///
/// Serialized as JSON and embedded in the agent's runbook via the
/// `{{audit_manifest}}` template variable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditManifest {
    pub agent_id: String,
    pub doc_files: Vec<String>,
    pub diagram_files: Vec<String>,
    pub source_dirs: Vec<String>,
    pub base_sha: String,
}

/// Partition candidate files across agents via round-robin distribution.
///
/// Each agent receives a disjoint subset of files and the union of source
/// directories for its assigned files (looked up via the scope map).
pub fn partition_audit(
    files: &[CandidateFile],
    scope_entries: &[ScopeEntry],
    agents_cap: usize,
    base_sha: &str,
) -> Vec<AuditManifest> {
    if files.is_empty() {
        return Vec::new();
    }

    let num_agents = agents_cap.min(files.len());
    let mut buckets: Vec<Vec<&CandidateFile>> = vec![Vec::new(); num_agents];

    for (i, file) in files.iter().enumerate() {
        buckets[i % num_agents].push(file);
    }

    buckets
        .into_iter()
        .enumerate()
        .filter(|(_, bucket)| !bucket.is_empty())
        .map(|(idx, bucket)| {
            let mut doc_files = Vec::new();
            let mut diagram_files = Vec::new();
            let mut source_dirs_set: HashSet<String> = HashSet::new();

            for file in &bucket {
                match file.kind {
                    FileKind::Doc => doc_files.push(file.path.clone()),
                    FileKind::Diagram => diagram_files.push(file.path.clone()),
                }
                for dir in doc_source_dirs(&file.path, scope_entries) {
                    source_dirs_set.insert(dir);
                }
            }

            let mut source_dirs: Vec<String> = source_dirs_set.into_iter().collect();
            source_dirs.sort();

            AuditManifest {
                agent_id: format!("batch-{:02}", idx + 1),
                doc_files,
                diagram_files,
                source_dirs,
                base_sha: base_sha.to_owned(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Runbook substitution
// ---------------------------------------------------------------------------

/// Substitute template variables in the audit runbook.
pub fn substitute_audit_runbook(
    template: &str,
    manifest: &AuditManifest,
    config: &AuditConfig,
    run_id: &str,
) -> String {
    let manifest_json = serde_json::to_string_pretty(manifest).unwrap_or_default();

    template
        .replace("{{repository}}", &config.repository)
        .replace("{{base_branch}}", &config.base_branch)
        .replace("{{base_sha}}", &manifest.base_sha)
        .replace("{{agent_id}}", &manifest.agent_id)
        .replace("{{run_id}}", run_id)
        .replace("{{audit_manifest}}", &manifest_json)
}

// ---------------------------------------------------------------------------
// State update
// ---------------------------------------------------------------------------

/// Build state entries for all files in the processed manifests.
///
/// Records the current blob SHA and timestamp for each file so that
/// unchanged files can be skipped on subsequent runs.
pub fn build_audit_state_update(
    manifests: &[AuditManifest],
    current_blobs: &HashMap<String, String>,
    run_id: &str,
) -> HashMap<String, AuditFileState> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut updates = HashMap::new();

    for manifest in manifests {
        let all_files = manifest
            .doc_files
            .iter()
            .chain(manifest.diagram_files.iter());

        for file_path in all_files {
            let blob_sha = current_blobs.get(file_path).cloned().unwrap_or_default();

            updates.insert(
                file_path.clone(),
                AuditFileState {
                    blob_sha,
                    processed_at: now.clone(),
                    run_id: run_id.to_owned(),
                },
            );
        }
    }

    updates
}

// ---------------------------------------------------------------------------
// Run ID generation
// ---------------------------------------------------------------------------

/// Generate a run ID for the audit pipeline.
///
/// Format: `audit-YYYY-MM-DD-HHMM`.
pub fn generate_audit_run_id() -> anyhow::Result<String> {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%d-%H%M"])
        .output()
        .context("failed to run `date` for audit run ID generation")?;

    let stamp = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok(format!("audit-{stamp}"))
}

/// Extract the date portion from an audit run ID (for PR titles and branch
/// names). Falls back to "unknown" if parsing fails.
pub fn audit_run_date(run_id: &str) -> &str {
    run_id
        .strip_prefix("audit-")
        .and_then(|s| s.get(..10))
        .unwrap_or("unknown")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Scope-map parsing ----------------------------------------------------

    #[test]
    fn parse_scope_map_basic() {
        let content = r#"
[[scopes]]
doc = "docs/identity.md"
dir = "crates/gossip-contracts/src/identity/"

[[scopes]]
doc = "docs/identity.md"
dir = "crates/gossip-contracts/src/shard/"

[[scopes]]
doc = "docs/coordination.md"
dir = "crates/gossip-coordination/src/"
"#;

        let tmp = std::env::temp_dir().join("test_scope_map.toml");
        std::fs::write(&tmp, content).unwrap();

        let entries = parse_scope_map(&tmp).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].doc, "docs/identity.md");
        assert_eq!(entries[0].dir, "crates/gossip-contracts/src/identity/");
    }

    #[test]
    fn doc_source_dirs_deduplicates() {
        let entries = vec![
            ScopeEntry {
                doc: "docs/a.md".into(),
                dir: "src/x/".into(),
            },
            ScopeEntry {
                doc: "docs/a.md".into(),
                dir: "src/y/".into(),
            },
            ScopeEntry {
                doc: "docs/a.md".into(),
                dir: "src/x/".into(), // duplicate
            },
            ScopeEntry {
                doc: "docs/b.md".into(),
                dir: "src/z/".into(),
            },
        ];

        let dirs = doc_source_dirs("docs/a.md", &entries);
        assert_eq!(dirs, vec!["src/x/", "src/y/"]);
    }

    #[test]
    fn doc_source_dirs_no_match() {
        let entries = vec![ScopeEntry {
            doc: "docs/a.md".into(),
            dir: "src/x/".into(),
        }];
        let dirs = doc_source_dirs("docs/missing.md", &entries);
        assert!(dirs.is_empty());
    }

    // -- Filtering ------------------------------------------------------------

    #[test]
    fn filter_unchanged_skips_matching_blobs() {
        let candidates = vec![
            CandidateFile {
                kind: FileKind::Doc,
                path: "docs/a.md".into(),
            },
            CandidateFile {
                kind: FileKind::Doc,
                path: "docs/b.md".into(),
            },
            CandidateFile {
                kind: FileKind::Diagram,
                path: "diagrams/c.md".into(),
            },
        ];

        let mut blobs = HashMap::new();
        blobs.insert("docs/a.md".to_owned(), "sha-a".to_owned());
        blobs.insert("docs/b.md".to_owned(), "sha-b".to_owned());
        blobs.insert("diagrams/c.md".to_owned(), "sha-c".to_owned());

        let mut state = HashMap::new();
        state.insert(
            "docs/a.md".to_owned(),
            AuditFileState {
                blob_sha: "sha-a".to_owned(),
                processed_at: String::new(),
                run_id: String::new(),
            },
        );
        // docs/b.md has a different SHA in state.
        state.insert(
            "docs/b.md".to_owned(),
            AuditFileState {
                blob_sha: "old-sha".to_owned(),
                processed_at: String::new(),
                run_id: String::new(),
            },
        );
        // diagrams/c.md not in state at all.

        let (to_process, skipped) = filter_unchanged(candidates, &blobs, &state, false);
        assert_eq!(skipped, 1); // only docs/a.md skipped
        assert_eq!(to_process.len(), 2);
        assert_eq!(to_process[0].path, "docs/b.md");
        assert_eq!(to_process[1].path, "diagrams/c.md");
    }

    #[test]
    fn filter_unchanged_full_mode_skips_nothing() {
        let candidates = vec![CandidateFile {
            kind: FileKind::Doc,
            path: "docs/a.md".into(),
        }];

        let mut blobs = HashMap::new();
        blobs.insert("docs/a.md".to_owned(), "sha-a".to_owned());

        let mut state = HashMap::new();
        state.insert(
            "docs/a.md".to_owned(),
            AuditFileState {
                blob_sha: "sha-a".to_owned(),
                processed_at: String::new(),
                run_id: String::new(),
            },
        );

        let (to_process, skipped) = filter_unchanged(candidates, &blobs, &state, true);
        assert_eq!(skipped, 0);
        assert_eq!(to_process.len(), 1);
    }

    // -- Partitioning ---------------------------------------------------------

    #[test]
    fn partition_round_robin() {
        let files: Vec<CandidateFile> = (0..7)
            .map(|i| CandidateFile {
                kind: if i < 5 {
                    FileKind::Doc
                } else {
                    FileKind::Diagram
                },
                path: format!("docs/file-{i}.md"),
            })
            .collect();

        let manifests = partition_audit(&files, &[], 3, "sha123");
        assert_eq!(manifests.len(), 3);

        // Round-robin: 3, 2, 2
        let total: usize = manifests
            .iter()
            .map(|m| m.doc_files.len() + m.diagram_files.len())
            .sum();
        assert_eq!(total, 7);

        assert_eq!(manifests[0].agent_id, "batch-01");
        assert_eq!(manifests[1].agent_id, "batch-02");
        assert_eq!(manifests[2].agent_id, "batch-03");

        // All manifests share the same base SHA.
        for m in &manifests {
            assert_eq!(m.base_sha, "sha123");
        }
    }

    #[test]
    fn partition_fewer_files_than_cap() {
        let files = vec![
            CandidateFile {
                kind: FileKind::Doc,
                path: "docs/a.md".into(),
            },
            CandidateFile {
                kind: FileKind::Doc,
                path: "docs/b.md".into(),
            },
        ];

        let manifests = partition_audit(&files, &[], 10, "sha");
        assert_eq!(manifests.len(), 2, "cap should not exceed file count");
    }

    #[test]
    fn partition_empty() {
        let manifests = partition_audit(&[], &[], 10, "sha");
        assert!(manifests.is_empty());
    }

    #[test]
    fn partition_includes_source_dirs() {
        let files = vec![CandidateFile {
            kind: FileKind::Doc,
            path: "docs/identity.md".into(),
        }];

        let entries = vec![
            ScopeEntry {
                doc: "docs/identity.md".into(),
                dir: "crates/gossip-contracts/src/identity/".into(),
            },
            ScopeEntry {
                doc: "docs/identity.md".into(),
                dir: "crates/gossip-contracts/src/shard/".into(),
            },
        ];

        let manifests = partition_audit(&files, &entries, 5, "sha");
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].source_dirs.len(), 2);
        assert!(
            manifests[0]
                .source_dirs
                .contains(&"crates/gossip-contracts/src/identity/".to_owned())
        );
    }

    // -- Runbook substitution -------------------------------------------------

    #[test]
    fn substitute_replaces_all_placeholders() {
        let template = "repo={{repository}} branch={{base_branch}} sha={{base_sha}} \
                         agent={{agent_id}} run={{run_id}} manifest={{audit_manifest}}";

        let manifest = AuditManifest {
            agent_id: "batch-01".into(),
            doc_files: vec!["docs/a.md".into()],
            diagram_files: vec![],
            source_dirs: vec!["src/x/".into()],
            base_sha: "abc123".into(),
        };

        let config = AuditConfig {
            repository: "org/repo".into(),
            base_branch: "main".into(),
            ..AuditConfig::default()
        };

        let result = substitute_audit_runbook(template, &manifest, &config, "run-42");

        assert!(result.contains("repo=org/repo"));
        assert!(result.contains("branch=main"));
        assert!(result.contains("sha=abc123"));
        assert!(result.contains("agent=batch-01"));
        assert!(result.contains("run=run-42"));
        assert!(result.contains("docs/a.md"));
    }

    // -- State update ---------------------------------------------------------

    #[test]
    fn build_state_update_covers_all_files() {
        let manifests = vec![
            AuditManifest {
                agent_id: "batch-01".into(),
                doc_files: vec!["docs/a.md".into()],
                diagram_files: vec!["diagrams/b.md".into()],
                source_dirs: vec![],
                base_sha: "sha".into(),
            },
            AuditManifest {
                agent_id: "batch-02".into(),
                doc_files: vec!["docs/c.md".into()],
                diagram_files: vec![],
                source_dirs: vec![],
                base_sha: "sha".into(),
            },
        ];

        let mut blobs = HashMap::new();
        blobs.insert("docs/a.md".to_owned(), "sha-a".to_owned());
        blobs.insert("diagrams/b.md".to_owned(), "sha-b".to_owned());
        blobs.insert("docs/c.md".to_owned(), "sha-c".to_owned());

        let updates = build_audit_state_update(&manifests, &blobs, "run-1");
        assert_eq!(updates.len(), 3);
        assert_eq!(updates["docs/a.md"].blob_sha, "sha-a");
        assert_eq!(updates["docs/a.md"].run_id, "run-1");
        assert_eq!(updates["diagrams/b.md"].blob_sha, "sha-b");
    }

    // -- Run ID ---------------------------------------------------------------

    #[test]
    fn audit_run_date_extracts_date() {
        assert_eq!(audit_run_date("audit-2026-04-05-1430"), "2026-04-05");
    }

    #[test]
    fn audit_run_date_fallback() {
        assert_eq!(audit_run_date("bad-format"), "unknown");
    }
}
