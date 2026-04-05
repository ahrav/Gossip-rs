//! Affected-chapter computation.
//!
//! Given a set of changed source files and the bipartite dependency graph,
//! determines the minimal set of documentation chapters that must be rebuilt.
//! Supports both incremental (changed-files-only) and full (all-chapters) modes.

use std::collections::{HashMap, HashSet};

use crate::graph::DependencyGraph;
use crate::state::{GuideSyncState, SourceFileState};

/// The set of chapters affected by source code changes, grouped by section.
#[derive(Debug, Clone)]
pub struct AffectedSet {
    /// All affected chapter IDs (e.g., `["01-04", "02-04", "04-07"]`).
    pub chapters: Vec<String>,
    /// Grouped by section: section ID -> chapter IDs within that section.
    pub by_section: HashMap<String, Vec<String>>,
}

/// Extract section ID from a chapter ID.
///
/// Splits on `'-'` and returns the first segment. For example, `"02-04"` yields
/// `"02"`. If no `'-'` is present, returns the full chapter ID as-is.
fn section_of(chapter_id: &str) -> &str {
    chapter_id.split('-').next().unwrap_or(chapter_id)
}

/// Build an `AffectedSet` from a deduplicated set of chapter IDs.
///
/// Sorts chapters globally, groups them by section, and sorts within each
/// section group for deterministic output.
fn build_affected_set(chapter_ids: HashSet<String>) -> AffectedSet {
    let mut chapters: Vec<String> = chapter_ids.into_iter().collect();
    chapters.sort();

    let mut by_section: HashMap<String, Vec<String>> = HashMap::new();
    for ch in &chapters {
        by_section
            .entry(section_of(ch).to_owned())
            .or_default()
            .push(ch.clone());
    }
    for group in by_section.values_mut() {
        group.sort();
    }

    AffectedSet {
        chapters,
        by_section,
    }
}

/// Compare current blob SHAs against stored state to detect changed files.
///
/// Returns paths where the blob SHA differs from the stored value or the file is
/// entirely new (not present in `stored`). Files that exist in `stored` but not
/// in `current_blobs` are ignored -- they represent deletions and do not trigger
/// chapter rebuilds.
pub fn detect_changed_sources(
    current_blobs: &HashMap<String, String>,
    stored: &HashMap<String, SourceFileState>,
) -> Vec<String> {
    let mut changed: Vec<String> = current_blobs
        .iter()
        .filter(|(path, current_sha)| {
            stored
                .get(path.as_str())
                .is_none_or(|s| s.blob_sha != **current_sha)
        })
        .map(|(path, _)| path.clone())
        .collect();
    changed.sort();
    changed
}

/// Compute the chapters that must be rebuilt given a set of changed source files.
///
/// Walks `graph.source_to_chapters` for each changed source to collect dependent
/// chapters, then applies an early-cutoff filter: chapters whose
/// `source_sha_at_update` already matches `current_source_sha` are excluded
/// because they are already synced to the current source snapshot.
pub fn compute_affected_chapters(
    changed_sources: &[String],
    graph: &DependencyGraph,
    guide_sync_state: &GuideSyncState,
    current_source_sha: &str,
) -> AffectedSet {
    let mut affected: HashSet<String> = HashSet::new();

    for src in changed_sources {
        if let Some(chapters) = graph.source_to_chapters.get(src) {
            for ch in chapters {
                affected.insert(ch.clone());
            }
        }
    }

    // Early cutoff: drop chapters already synced to this exact source snapshot.
    affected.retain(|ch| {
        guide_sync_state
            .chapters
            .get(ch)
            .is_none_or(|state| state.source_sha_at_update != current_source_sha)
    });

    build_affected_set(affected)
}

/// Compute an `AffectedSet` containing every chapter in the dependency graph.
///
/// Used for `--full` mode where all chapters are rebuilt regardless of source
/// changes. No filtering or early-cutoff is applied.
pub fn compute_affected_full(graph: &DependencyGraph) -> AffectedSet {
    let all_chapters: HashSet<String> = graph.chapter_to_sources.keys().cloned().collect();
    build_affected_set(all_chapters)
}

/// Log the fan-out of each changed source file.
///
/// Files that fan out to 3 or more chapters are logged at `warn` level as
/// bottleneck files; others are logged at `info` level. This helps operators
/// spot high-impact source files that trigger many chapter rebuilds.
pub fn log_bottleneck_report(changed_sources: &[String], graph: &DependencyGraph) {
    /// Fan-out threshold above which a file is considered a bottleneck.
    const BOTTLENECK_THRESHOLD: usize = 3;

    for src in changed_sources {
        let fan_out = graph.source_to_chapters.get(src).map_or(0, |chs| chs.len());

        if fan_out >= BOTTLENECK_THRESHOLD {
            tracing::warn!(
                file = %src,
                fan_out,
                "bottleneck source file: changes fan out to {fan_out} chapters",
            );
        } else {
            tracing::info!(
                file = %src,
                fan_out,
                "source file changed, affects {fan_out} chapter(s)",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ChapterState, ChapterStatus, SourceFileState};

    /// Build a minimal dependency graph for testing.
    fn test_graph() -> DependencyGraph {
        let mut source_to_chapters: HashMap<String, Vec<String>> = HashMap::new();
        source_to_chapters.insert(
            "src/identity/types.rs".to_owned(),
            vec!["01-04".to_owned(), "02-04".to_owned()],
        );
        source_to_chapters.insert(
            "src/identity/hashing.rs".to_owned(),
            vec!["01-01".to_owned(), "01-02".to_owned(), "02-02".to_owned()],
        );
        source_to_chapters.insert(
            "src/coordination/mod.rs".to_owned(),
            vec!["04-01".to_owned()],
        );

        let mut chapter_to_sources: HashMap<String, Vec<String>> = HashMap::new();
        chapter_to_sources.insert("01-04".to_owned(), vec!["src/identity/types.rs".to_owned()]);
        chapter_to_sources.insert("02-04".to_owned(), vec!["src/identity/types.rs".to_owned()]);
        chapter_to_sources.insert(
            "01-01".to_owned(),
            vec!["src/identity/hashing.rs".to_owned()],
        );
        chapter_to_sources.insert(
            "01-02".to_owned(),
            vec!["src/identity/hashing.rs".to_owned()],
        );
        chapter_to_sources.insert(
            "02-02".to_owned(),
            vec!["src/identity/hashing.rs".to_owned()],
        );
        chapter_to_sources.insert(
            "04-01".to_owned(),
            vec!["src/coordination/mod.rs".to_owned()],
        );

        DependencyGraph {
            source_to_chapters,
            chapter_to_sources,
            section_to_crates: HashMap::new(),
        }
    }

    fn make_chapter_state(source_sha_at_update: &str) -> ChapterState {
        ChapterState {
            blob_sha: String::new(),
            last_updated_run: String::new(),
            source_sha_at_update: source_sha_at_update.to_owned(),
            status: ChapterStatus::Current,
        }
    }

    // -----------------------------------------------------------------------
    // section_of
    // -----------------------------------------------------------------------

    #[test]
    fn section_of_extracts_first_segment() {
        assert_eq!(section_of("02-04"), "02");
        assert_eq!(section_of("14-01"), "14");
    }

    #[test]
    fn section_of_no_separator_returns_full_id() {
        assert_eq!(section_of("appendix"), "appendix");
    }

    #[test]
    fn section_of_multiple_separators_returns_first() {
        assert_eq!(section_of("02-04-sub"), "02");
    }

    // -----------------------------------------------------------------------
    // detect_changed_sources
    // -----------------------------------------------------------------------

    #[test]
    fn detect_changed_new_file() {
        let current = HashMap::from([("src/new.rs".to_owned(), "sha-new".to_owned())]);
        let stored = HashMap::new();

        let changed = detect_changed_sources(&current, &stored);
        assert_eq!(changed, vec!["src/new.rs"]);
    }

    #[test]
    fn detect_changed_modified_file() {
        let current = HashMap::from([("src/lib.rs".to_owned(), "sha-v2".to_owned())]);
        let stored = HashMap::from([(
            "src/lib.rs".to_owned(),
            SourceFileState {
                blob_sha: "sha-v1".to_owned(),
                dependent_chapters: vec![],
            },
        )]);

        let changed = detect_changed_sources(&current, &stored);
        assert_eq!(changed, vec!["src/lib.rs"]);
    }

    #[test]
    fn detect_changed_unchanged_file() {
        let current = HashMap::from([("src/lib.rs".to_owned(), "sha-same".to_owned())]);
        let stored = HashMap::from([(
            "src/lib.rs".to_owned(),
            SourceFileState {
                blob_sha: "sha-same".to_owned(),
                dependent_chapters: vec![],
            },
        )]);

        let changed = detect_changed_sources(&current, &stored);
        assert!(changed.is_empty());
    }

    #[test]
    fn detect_changed_mixed() {
        let current = HashMap::from([
            ("src/new.rs".to_owned(), "sha-a".to_owned()),
            ("src/changed.rs".to_owned(), "sha-b2".to_owned()),
            ("src/same.rs".to_owned(), "sha-c".to_owned()),
        ]);
        let stored = HashMap::from([
            (
                "src/changed.rs".to_owned(),
                SourceFileState {
                    blob_sha: "sha-b1".to_owned(),
                    dependent_chapters: vec![],
                },
            ),
            (
                "src/same.rs".to_owned(),
                SourceFileState {
                    blob_sha: "sha-c".to_owned(),
                    dependent_chapters: vec![],
                },
            ),
        ]);

        let changed = detect_changed_sources(&current, &stored);
        // Sorted output: changed.rs, new.rs.
        assert_eq!(changed, vec!["src/changed.rs", "src/new.rs"]);
    }

    // -----------------------------------------------------------------------
    // compute_affected_chapters
    // -----------------------------------------------------------------------

    #[test]
    fn affected_chapters_basic_propagation() {
        let graph = test_graph();
        let gs = GuideSyncState::default();

        let changed = vec!["src/identity/types.rs".to_owned()];
        let result = compute_affected_chapters(&changed, &graph, &gs, "sha-current");

        assert_eq!(result.chapters, vec!["01-04", "02-04"]);
    }

    #[test]
    fn affected_chapters_union_across_sources() {
        let graph = test_graph();
        let gs = GuideSyncState::default();

        let changed = vec![
            "src/identity/types.rs".to_owned(),
            "src/identity/hashing.rs".to_owned(),
        ];
        let result = compute_affected_chapters(&changed, &graph, &gs, "sha-current");

        // Union of {01-04, 02-04} and {01-01, 01-02, 02-02}.
        assert_eq!(
            result.chapters,
            vec!["01-01", "01-02", "01-04", "02-02", "02-04"]
        );
    }

    #[test]
    fn affected_chapters_early_cutoff() {
        let graph = test_graph();
        let mut gs = GuideSyncState::default();

        // Mark 01-04 as already synced to the current source SHA.
        gs.chapters
            .insert("01-04".to_owned(), make_chapter_state("sha-current"));

        let changed = vec!["src/identity/types.rs".to_owned()];
        let result = compute_affected_chapters(&changed, &graph, &gs, "sha-current");

        // 01-04 is excluded because it matches the current source SHA.
        assert_eq!(result.chapters, vec!["02-04"]);
    }

    #[test]
    fn affected_chapters_early_cutoff_different_sha_still_included() {
        let graph = test_graph();
        let mut gs = GuideSyncState::default();

        // Chapter was synced to a different (older) SHA.
        gs.chapters
            .insert("01-04".to_owned(), make_chapter_state("sha-old"));

        let changed = vec!["src/identity/types.rs".to_owned()];
        let result = compute_affected_chapters(&changed, &graph, &gs, "sha-current");

        // Both chapters included because 01-04's stored SHA differs.
        assert_eq!(result.chapters, vec!["01-04", "02-04"]);
    }

    #[test]
    fn affected_chapters_grouping_by_section() {
        let graph = test_graph();
        let gs = GuideSyncState::default();

        let changed = vec![
            "src/identity/types.rs".to_owned(),
            "src/identity/hashing.rs".to_owned(),
            "src/coordination/mod.rs".to_owned(),
        ];
        let result = compute_affected_chapters(&changed, &graph, &gs, "sha-current");

        assert_eq!(
            result.by_section.get("01").unwrap(),
            &["01-01", "01-02", "01-04"]
        );
        assert_eq!(result.by_section.get("02").unwrap(), &["02-02", "02-04"]);
        assert_eq!(result.by_section.get("04").unwrap(), &["04-01"]);
        assert_eq!(result.by_section.len(), 3);
    }

    #[test]
    fn affected_chapters_empty_changes() {
        let graph = test_graph();
        let gs = GuideSyncState::default();

        let result = compute_affected_chapters(&[], &graph, &gs, "sha-current");

        assert!(result.chapters.is_empty());
        assert!(result.by_section.is_empty());
    }

    #[test]
    fn affected_chapters_unknown_source_file() {
        let graph = test_graph();
        let gs = GuideSyncState::default();

        let changed = vec!["src/unknown/file.rs".to_owned()];
        let result = compute_affected_chapters(&changed, &graph, &gs, "sha-current");

        // Unknown files have no edges in the graph, so no chapters are affected.
        assert!(result.chapters.is_empty());
        assert!(result.by_section.is_empty());
    }

    // -----------------------------------------------------------------------
    // compute_affected_full
    // -----------------------------------------------------------------------

    #[test]
    fn affected_full_returns_all_chapters() {
        let graph = test_graph();

        let result = compute_affected_full(&graph);

        assert_eq!(
            result.chapters,
            vec!["01-01", "01-02", "01-04", "02-02", "02-04", "04-01"]
        );
    }

    #[test]
    fn affected_full_groups_by_section() {
        let graph = test_graph();

        let result = compute_affected_full(&graph);

        assert_eq!(
            result.by_section.get("01").unwrap(),
            &["01-01", "01-02", "01-04"]
        );
        assert_eq!(result.by_section.get("02").unwrap(), &["02-02", "02-04"]);
        assert_eq!(result.by_section.get("04").unwrap(), &["04-01"]);
    }

    #[test]
    fn affected_full_empty_graph() {
        let graph = DependencyGraph {
            source_to_chapters: HashMap::new(),
            chapter_to_sources: HashMap::new(),
            section_to_crates: HashMap::new(),
        };

        let result = compute_affected_full(&graph);

        assert!(result.chapters.is_empty());
        assert!(result.by_section.is_empty());
    }

    // -----------------------------------------------------------------------
    // log_bottleneck_report (smoke test -- verifies no panics)
    // -----------------------------------------------------------------------

    #[test]
    fn bottleneck_report_does_not_panic() {
        let graph = test_graph();
        let changed = vec![
            "src/identity/types.rs".to_owned(),
            "src/identity/hashing.rs".to_owned(),
            "src/unknown/file.rs".to_owned(),
        ];
        // Smoke test: should not panic regardless of tracing subscriber state.
        log_bottleneck_report(&changed, &graph);
    }
}
