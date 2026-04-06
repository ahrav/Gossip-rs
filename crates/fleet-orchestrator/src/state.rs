//! Fleet state management.
//!
//! Tracks the lifecycle of each chapter build across the fleet: pending,
//! dispatched, succeeded, or failed. Persists state to disk so the orchestrator
//! can resume after interruption without re-dispatching completed work.
//!
//! All disk I/O uses an exclusive file lock (via `fs2`) to prevent concurrent
//! orchestrator processes from corrupting the shared `.fleet-state.json` file.
//! Writes are atomic: content goes to a `.tmp` sibling first, then is renamed
//! into place so readers never see a partial file.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::path::Path;

use anyhow::{Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Top-level fleet state, keyed by fleet type namespace.
/// Contains doc-rigor, design-doc-audit, and guide-sync namespaces.
/// Unknown namespaces are preserved through round-trips.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FleetState {
    #[serde(flatten)]
    pub namespaces: HashMap<String, serde_json::Value>,
}

/// Guide-sync specific state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuideSyncState {
    pub meta: GuideSyncMeta,
    pub source_files: HashMap<String, SourceFileState>,
    pub chapters: HashMap<String, ChapterState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuideSyncMeta {
    pub last_run_id: String,
    pub source_sha: String,
    pub guide_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFileState {
    pub blob_sha: String,
    pub dependent_chapters: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChapterState {
    pub blob_sha: String,
    pub last_updated_run: String,
    pub source_sha_at_update: String,
    pub status: ChapterStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChapterStatus {
    Current,
    Stale,
}

/// Result of a single agent's execution.
#[derive(Debug, Clone)]
pub struct AgentResult {
    pub agent_id: String,
    pub status: AgentStatus,
    pub branch_pushed: bool,
    pub merge_succeeded: bool,
    pub chapters_updated: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStatus {
    Completed,
    Failed,
    Timeout,
}

// ---------------------------------------------------------------------------
// File locking helper
// ---------------------------------------------------------------------------

/// Suffix appended to the state file path to derive the lock file path.
const LOCK_SUFFIX: &str = ".lock";

/// Derive the lock-file path from the state file path.
fn lock_path(state_path: &Path) -> std::path::PathBuf {
    let mut p = state_path.as_os_str().to_owned();
    p.push(LOCK_SUFFIX);
    p.into()
}

/// Execute `f` while holding an exclusive flock on the lock file adjacent to
/// `state_path`. The lock file is created if it does not exist.
fn with_lock<T>(state_path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let lp = lock_path(state_path);
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lp)
        .with_context(|| format!("open lock file {}", lp.display()))?;
    lock_file
        .lock_exclusive()
        .with_context(|| format!("acquire exclusive lock on {}", lp.display()))?;

    let result = f();

    // Best-effort unlock; the OS releases the lock when the fd drops anyway.
    let _ = lock_file.unlock();
    result
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Read the fleet state from disk, returning `Default` if the file is absent.
///
/// Acquires an exclusive file lock for the duration of the read so that
/// concurrent writers cannot produce a torn read.
pub fn read_state(path: &Path) -> Result<FleetState> {
    with_lock(path, || {
        if !path.exists() {
            return Ok(FleetState::default());
        }
        let contents =
            fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        if contents.trim().is_empty() {
            return Ok(FleetState::default());
        }
        serde_json::from_str(&contents)
            .with_context(|| format!("deserialize fleet state from {}", path.display()))
    })
}

/// Write the fleet state to disk atomically.
///
/// Writes to a `.tmp` sibling first, then renames into place so that readers
/// never observe a partially-written file. An exclusive file lock serialises
/// concurrent callers.
pub fn write_state(path: &Path, state: &FleetState) -> Result<()> {
    with_lock(path, || {
        let tmp_path = {
            let mut p = path.as_os_str().to_owned();
            p.push(".tmp");
            std::path::PathBuf::from(p)
        };

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent dirs for {}", path.display()))?;
        }

        let serialized =
            serde_json::to_string_pretty(state).context("serialize fleet state to JSON")?;
        fs::write(&tmp_path, serialized)
            .with_context(|| format!("write tmp file {}", tmp_path.display()))?;

        fs::rename(&tmp_path, path).with_context(|| {
            format!("atomic rename {} -> {}", tmp_path.display(), path.display())
        })?;

        Ok(())
    })
}

/// Atomic read-modify-write cycle.
///
/// Holds an exclusive lock for the entire duration so that no other process
/// can interleave a write between our read and our write-back.
pub fn update_state<F>(path: &Path, updater: F) -> Result<()>
where
    F: FnOnce(&mut FleetState),
{
    with_lock(path, || {
        let mut state = if path.exists() {
            let contents =
                fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
            if contents.trim().is_empty() {
                FleetState::default()
            } else {
                serde_json::from_str(&contents)
                    .with_context(|| format!("deserialize fleet state from {}", path.display()))?
            }
        } else {
            FleetState::default()
        };

        updater(&mut state);

        let tmp_path = {
            let mut p = path.as_os_str().to_owned();
            p.push(".tmp");
            std::path::PathBuf::from(p)
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent dirs for {}", path.display()))?;
        }

        let serialized =
            serde_json::to_string_pretty(&state).context("serialize fleet state to JSON")?;
        fs::write(&tmp_path, &serialized)
            .with_context(|| format!("write tmp file {}", tmp_path.display()))?;

        fs::rename(&tmp_path, path).with_context(|| {
            format!("atomic rename {} -> {}", tmp_path.display(), path.display())
        })?;

        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Audit namespace helpers
// ---------------------------------------------------------------------------

/// Namespace key used for design-doc-audit data inside `FleetState`.
const AUDIT_NS: &str = "design-doc-audit";

/// Per-file state for the design-doc-audit pipeline.
///
/// Tracks the blob SHA at the time of last successful audit so that unchanged
/// files can be skipped on subsequent runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFileState {
    pub blob_sha: String,
    pub processed_at: String,
    pub run_id: String,
}

/// Extract and deserialize the design-doc-audit namespace from a `FleetState`.
/// Returns an empty map when the namespace is absent.
pub fn get_audit_state(state: &FleetState) -> Result<HashMap<String, AuditFileState>> {
    match state.namespaces.get(AUDIT_NS) {
        Some(value) => serde_json::from_value(value.clone())
            .context("deserialize design-doc-audit namespace from fleet state"),
        None => Ok(HashMap::new()),
    }
}

/// Serialize and set the design-doc-audit namespace inside a `FleetState`.
pub fn set_audit_state(
    state: &mut FleetState,
    audit: &HashMap<String, AuditFileState>,
) -> Result<()> {
    let value =
        serde_json::to_value(audit).context("serialize design-doc-audit state to JSON value")?;
    state.namespaces.insert(AUDIT_NS.to_owned(), value);
    Ok(())
}

// ---------------------------------------------------------------------------
// Guide-sync namespace helpers
// ---------------------------------------------------------------------------

/// Namespace key used for guide-sync data inside `FleetState`.
const GUIDE_SYNC_NS: &str = "guide-sync";

/// Extract and deserialize the guide-sync namespace from a `FleetState`.
/// Returns `Default` when the namespace is absent.
pub fn get_guide_sync_state(state: &FleetState) -> Result<GuideSyncState> {
    match state.namespaces.get(GUIDE_SYNC_NS) {
        Some(value) => serde_json::from_value(value.clone())
            .context("deserialize guide-sync namespace from fleet state"),
        None => Ok(GuideSyncState::default()),
    }
}

/// Serialize and set the guide-sync namespace inside a `FleetState`.
pub fn set_guide_sync_state(state: &mut FleetState, gs: &GuideSyncState) -> Result<()> {
    let value = serde_json::to_value(gs).context("serialize guide-sync state to JSON value")?;
    state.namespaces.insert(GUIDE_SYNC_NS.to_owned(), value);
    Ok(())
}

// ---------------------------------------------------------------------------
// Success-only agent result application
// ---------------------------------------------------------------------------

/// Apply agent results to the guide-sync state.
///
/// Only agents that completed successfully **and** whose merge succeeded have
/// their chapters promoted to `Current`. Chapters owned by failed or timed-out
/// agents are marked `Stale` so they are retried on the next run.
///
/// `current_blobs` maps file paths and chapter names to their current blob
/// SHAs, used to update `source_files` and `chapters` entries.
pub fn update_for_successful_agents(
    gs: &mut GuideSyncState,
    results: &[AgentResult],
    source_sha: &str,
    run_id: &str,
    current_blobs: &HashMap<String, String>,
) {
    for result in results {
        let success = result.status == AgentStatus::Completed && result.merge_succeeded;

        for chapter_name in &result.chapters_updated {
            if success {
                let blob_sha = current_blobs.get(chapter_name).cloned().unwrap_or_default();

                gs.chapters.insert(
                    chapter_name.clone(),
                    ChapterState {
                        blob_sha,
                        last_updated_run: run_id.to_owned(),
                        source_sha_at_update: source_sha.to_owned(),
                        status: ChapterStatus::Current,
                    },
                );
            } else {
                // Mark as stale so the next run retries this chapter.
                if let Some(ch) = gs.chapters.get_mut(chapter_name) {
                    ch.status = ChapterStatus::Stale;
                } else {
                    gs.chapters.insert(
                        chapter_name.clone(),
                        ChapterState {
                            blob_sha: String::new(),
                            last_updated_run: String::new(),
                            source_sha_at_update: String::new(),
                            status: ChapterStatus::Stale,
                        },
                    );
                }
            }
        }

        // Update source file blob SHAs for successful agents.
        if success {
            for chapter_name in &result.chapters_updated {
                for (file_path, file_state) in &mut gs.source_files {
                    if file_state.dependent_chapters.contains(chapter_name)
                        && let Some(sha) = current_blobs.get(file_path)
                    {
                        file_state.blob_sha = sha.clone();
                    }
                }
            }
        }
    }

    gs.meta.last_run_id = run_id.to_owned();
    gs.meta.source_sha = source_sha.to_owned();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Create a unique temporary directory for test isolation.
    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("fleet_orchestrator_tests")
            .join(name)
            .join(format!("{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[test]
    fn read_missing_file_returns_default() {
        let dir = test_dir("read_missing");
        let path = dir.join("nonexistent.json");
        let state = read_state(&path).unwrap();
        assert!(state.namespaces.is_empty());
    }

    #[test]
    fn write_then_read_roundtrip() {
        let dir = test_dir("roundtrip");
        let path = dir.join("state.json");

        let mut state = FleetState::default();
        state.namespaces.insert(
            "doc-rigor".to_owned(),
            serde_json::json!({"last_run": "abc123"}),
        );

        write_state(&path, &state).unwrap();
        let loaded = read_state(&path).unwrap();

        assert_eq!(
            loaded.namespaces.get("doc-rigor"),
            state.namespaces.get("doc-rigor"),
        );
    }

    #[test]
    fn update_state_applies_mutation() {
        let dir = test_dir("update_mutation");
        let path = dir.join("state.json");

        // Seed initial state.
        let initial = FleetState::default();
        write_state(&path, &initial).unwrap();

        update_state(&path, |s| {
            s.namespaces.insert(
                "design-doc-audit".to_owned(),
                serde_json::json!({"count": 42}),
            );
        })
        .unwrap();

        let loaded = read_state(&path).unwrap();
        assert_eq!(
            loaded.namespaces["design-doc-audit"],
            serde_json::json!({"count": 42}),
        );
    }

    #[test]
    fn update_state_on_missing_file_creates_it() {
        let dir = test_dir("update_creates");
        let path = dir.join("state.json");

        update_state(&path, |s| {
            s.namespaces
                .insert("new-ns".to_owned(), serde_json::json!("hello"));
        })
        .unwrap();

        assert!(path.exists());
        let loaded = read_state(&path).unwrap();
        assert_eq!(loaded.namespaces["new-ns"], serde_json::json!("hello"));
    }

    #[test]
    fn guide_sync_namespace_roundtrip() {
        let mut state = FleetState::default();

        // Also set a sibling namespace to verify it is preserved.
        state
            .namespaces
            .insert("doc-rigor".to_owned(), serde_json::json!({"version": 1}));

        let mut gs = GuideSyncState::default();
        gs.meta.last_run_id = "run-001".to_owned();
        gs.meta.source_sha = "aaa".to_owned();
        gs.source_files.insert(
            "src/lib.rs".to_owned(),
            SourceFileState {
                blob_sha: "bbb".to_owned(),
                dependent_chapters: vec!["ch1".to_owned()],
            },
        );
        gs.chapters.insert(
            "ch1".to_owned(),
            ChapterState {
                blob_sha: "ccc".to_owned(),
                last_updated_run: "run-001".to_owned(),
                source_sha_at_update: "aaa".to_owned(),
                status: ChapterStatus::Current,
            },
        );

        set_guide_sync_state(&mut state, &gs).unwrap();

        // Sibling namespace must still be present.
        assert!(state.namespaces.contains_key("doc-rigor"));

        let recovered = get_guide_sync_state(&state).unwrap();
        assert_eq!(recovered.meta.last_run_id, "run-001");
        assert_eq!(recovered.meta.source_sha, "aaa");
        assert!(recovered.source_files.contains_key("src/lib.rs"));
        assert_eq!(recovered.chapters["ch1"].status, ChapterStatus::Current,);
    }

    #[test]
    fn get_guide_sync_state_returns_default_when_absent() {
        let state = FleetState::default();
        let gs = get_guide_sync_state(&state).unwrap();
        assert!(gs.source_files.is_empty());
        assert!(gs.chapters.is_empty());
        assert!(gs.meta.last_run_id.is_empty());
    }

    #[test]
    fn successful_agent_updates_chapters_to_current() {
        let mut gs = GuideSyncState::default();
        let mut blobs = HashMap::new();
        blobs.insert("ch1".to_owned(), "sha-ch1".to_owned());
        blobs.insert("ch2".to_owned(), "sha-ch2".to_owned());

        let results = vec![AgentResult {
            agent_id: "agent-1".to_owned(),
            status: AgentStatus::Completed,
            branch_pushed: true,
            merge_succeeded: true,
            chapters_updated: vec!["ch1".to_owned(), "ch2".to_owned()],
        }];

        update_for_successful_agents(&mut gs, &results, "src-sha-1", "run-42", &blobs);

        assert_eq!(gs.chapters["ch1"].status, ChapterStatus::Current);
        assert_eq!(gs.chapters["ch1"].blob_sha, "sha-ch1");
        assert_eq!(gs.chapters["ch1"].last_updated_run, "run-42");
        assert_eq!(gs.chapters["ch1"].source_sha_at_update, "src-sha-1");

        assert_eq!(gs.chapters["ch2"].status, ChapterStatus::Current);
        assert_eq!(gs.meta.last_run_id, "run-42");
        assert_eq!(gs.meta.source_sha, "src-sha-1");
    }

    #[test]
    fn failed_agent_marks_chapters_stale() {
        let mut gs = GuideSyncState::default();
        // Pre-populate a chapter as Current.
        gs.chapters.insert(
            "ch1".to_owned(),
            ChapterState {
                blob_sha: "old-sha".to_owned(),
                last_updated_run: "run-1".to_owned(),
                source_sha_at_update: "old-src".to_owned(),
                status: ChapterStatus::Current,
            },
        );

        let results = vec![AgentResult {
            agent_id: "agent-fail".to_owned(),
            status: AgentStatus::Failed,
            branch_pushed: true,
            merge_succeeded: false,
            chapters_updated: vec!["ch1".to_owned(), "ch-new".to_owned()],
        }];

        update_for_successful_agents(&mut gs, &results, "src-sha-2", "run-43", &HashMap::new());

        // Existing chapter demoted to Stale but retains old metadata.
        assert_eq!(gs.chapters["ch1"].status, ChapterStatus::Stale);
        assert_eq!(gs.chapters["ch1"].blob_sha, "old-sha");

        // Previously unknown chapter created as Stale placeholder.
        assert_eq!(gs.chapters["ch-new"].status, ChapterStatus::Stale);

        // Meta still updated to record the run.
        assert_eq!(gs.meta.last_run_id, "run-43");
    }

    #[test]
    fn mixed_agents_only_success_updates_state() {
        let mut gs = GuideSyncState::default();
        let mut blobs = HashMap::new();
        blobs.insert("ch-ok".to_owned(), "sha-ok".to_owned());

        let results = vec![
            AgentResult {
                agent_id: "good-agent".to_owned(),
                status: AgentStatus::Completed,
                branch_pushed: true,
                merge_succeeded: true,
                chapters_updated: vec!["ch-ok".to_owned()],
            },
            AgentResult {
                agent_id: "timeout-agent".to_owned(),
                status: AgentStatus::Timeout,
                branch_pushed: false,
                merge_succeeded: false,
                chapters_updated: vec!["ch-timeout".to_owned()],
            },
            AgentResult {
                agent_id: "merge-fail".to_owned(),
                status: AgentStatus::Completed,
                branch_pushed: true,
                merge_succeeded: false,
                chapters_updated: vec!["ch-merge-fail".to_owned()],
            },
        ];

        update_for_successful_agents(&mut gs, &results, "src-sha-3", "run-44", &blobs);

        assert_eq!(gs.chapters["ch-ok"].status, ChapterStatus::Current);
        assert_eq!(gs.chapters["ch-timeout"].status, ChapterStatus::Stale);
        // Completed but merge failed -- still not promoted.
        assert_eq!(gs.chapters["ch-merge-fail"].status, ChapterStatus::Stale,);
    }

    #[test]
    fn successful_agent_updates_source_file_blobs() {
        let mut gs = GuideSyncState::default();
        gs.source_files.insert(
            "src/main.rs".to_owned(),
            SourceFileState {
                blob_sha: "old-blob".to_owned(),
                dependent_chapters: vec!["ch1".to_owned()],
            },
        );

        let mut blobs = HashMap::new();
        blobs.insert("ch1".to_owned(), "new-ch-sha".to_owned());
        blobs.insert("src/main.rs".to_owned(), "new-src-blob".to_owned());

        let results = vec![AgentResult {
            agent_id: "agent-ok".to_owned(),
            status: AgentStatus::Completed,
            branch_pushed: true,
            merge_succeeded: true,
            chapters_updated: vec!["ch1".to_owned()],
        }];

        update_for_successful_agents(&mut gs, &results, "src-sha", "run-50", &blobs);

        assert_eq!(gs.source_files["src/main.rs"].blob_sha, "new-src-blob");
    }

    #[test]
    fn atomic_write_does_not_leave_tmp_file() {
        let dir = test_dir("atomic_no_tmp");
        let path = dir.join("state.json");

        let state = FleetState::default();
        write_state(&path, &state).unwrap();

        let tmp_path = {
            let mut p = path.as_os_str().to_owned();
            p.push(".tmp");
            PathBuf::from(p)
        };

        // The .tmp file should have been renamed away.
        assert!(!tmp_path.exists());
        assert!(path.exists());
    }

    #[test]
    fn namespaces_preserved_across_disk_roundtrip() {
        let dir = test_dir("ns_preserve");
        let path = dir.join("state.json");

        let mut state = FleetState::default();
        state
            .namespaces
            .insert("doc-rigor".to_owned(), serde_json::json!({"pass": true}));
        state.namespaces.insert(
            "design-doc-audit".to_owned(),
            serde_json::json!({"audited": 5}),
        );

        let mut gs = GuideSyncState::default();
        gs.meta.last_run_id = "run-1".to_owned();
        set_guide_sync_state(&mut state, &gs).unwrap();

        write_state(&path, &state).unwrap();
        let loaded = read_state(&path).unwrap();

        // All three namespaces survive the round-trip.
        assert!(loaded.namespaces.contains_key("doc-rigor"));
        assert!(loaded.namespaces.contains_key("design-doc-audit"));
        assert!(loaded.namespaces.contains_key("guide-sync"));

        let recovered_gs = get_guide_sync_state(&loaded).unwrap();
        assert_eq!(recovered_gs.meta.last_run_id, "run-1");
    }

    #[test]
    fn audit_state_namespace_roundtrip() {
        let mut state = FleetState::default();

        let mut audit = HashMap::new();
        audit.insert(
            "docs/README.md".to_owned(),
            AuditFileState {
                blob_sha: "abc123".to_owned(),
                processed_at: "2026-04-04T00:00:00Z".to_owned(),
                run_id: "audit-2026-04-04".to_owned(),
            },
        );

        set_audit_state(&mut state, &audit).unwrap();

        let recovered = get_audit_state(&state).unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered["docs/README.md"].blob_sha, "abc123");
        assert_eq!(recovered["docs/README.md"].run_id, "audit-2026-04-04");
    }

    #[test]
    fn get_audit_state_returns_empty_when_absent() {
        let state = FleetState::default();
        let audit = get_audit_state(&state).unwrap();
        assert!(audit.is_empty());
    }

    #[test]
    fn audit_state_preserves_sibling_namespaces() {
        let mut state = FleetState::default();
        state
            .namespaces
            .insert("guide-sync".to_owned(), serde_json::json!({"meta": {}}));

        let audit = HashMap::new();
        set_audit_state(&mut state, &audit).unwrap();

        assert!(state.namespaces.contains_key("guide-sync"));
        assert!(state.namespaces.contains_key("design-doc-audit"));
    }
}
