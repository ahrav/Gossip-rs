//! Bipartite dependency graph.
//!
//! Models the relationship between source files and documentation chapters as a
//! bipartite graph. Source nodes represent files in the repository; chapter nodes
//! represent sections of the generated documentation. Edges encode which source
//! files contribute to which chapters, enabling efficient impact analysis when a
//! set of source files changes.

use std::collections::HashMap;
use std::path::Path;

/// Bipartite dependency graph: source files <-> guide chapters.
///
/// Both maps are kept in sync so that every source file referenced in
/// `chapter_to_sources` also appears as a key in `source_to_chapters`, and
/// vice versa. The `section_to_crates` map is a separate static mapping from
/// guide sections (two-digit prefix) to primary crate directories.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DependencyGraph {
    /// Source file path -> list of chapter IDs that reference it.
    pub source_to_chapters: HashMap<String, Vec<String>>,
    /// Chapter ID -> list of source file paths it references.
    pub chapter_to_sources: HashMap<String, Vec<String>>,
    /// Section ID (two-digit prefix) -> primary crate directories.
    pub section_to_crates: HashMap<String, Vec<String>>,
}

impl DependencyGraph {
    /// Serialize the graph to JSON and write it to `path`.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Deserialize a graph from a JSON file at `path`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let graph: Self = serde_json::from_str(&content)?;
        Ok(graph)
    }

    /// Return source files referenced by at least `threshold` chapters.
    ///
    /// These are bottleneck files whose modification fans out to many chapters.
    /// Results are sorted by degree descending, then by path ascending for
    /// deterministic output.
    pub fn high_degree_sources(&self, threshold: usize) -> Vec<(&str, usize)> {
        let mut results: Vec<(&str, usize)> = self
            .source_to_chapters
            .iter()
            .filter(|(_, chapters)| chapters.len() >= threshold)
            .map(|(path, chapters)| (path.as_str(), chapters.len()))
            .collect();
        results.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        results
    }
}

/// Build the static section-to-crates mapping.
///
/// Each two-digit section prefix maps to the primary crate directories whose
/// source files are covered by that section. Sections that are cross-cutting
/// or conceptual map to an empty list.
fn build_section_to_crates() -> HashMap<String, Vec<String>> {
    let entries: &[(&str, &[&str])] = &[
        ("00", &[]),
        ("01", &["gossip-contracts/src/identity/"]),
        ("02", &["gossip-contracts/src/identity/"]),
        ("03", &[]),
        (
            "04",
            &[
                "gossip-contracts/src/coordination/",
                "gossip-coordination/src/",
                "gossip-coordination-etcd/src/",
            ],
        ),
        ("05", &["gossip-frontier/src/"]),
        (
            "06",
            &[
                "gossip-contracts/src/connector/",
                "gossip-connectors/src/",
                "gossip-scanner-runtime/src/",
            ],
        ),
        (
            "07",
            &[
                "gossip-contracts/src/persistence/",
                "gossip-persistence-inmemory/src/",
            ],
        ),
        ("08", &[]),
        ("09", &[]),
        ("10", &["scanner-engine/src/"]),
        (
            "11",
            &[
                "gossip-scanner-runtime/src/",
                "scanner-scheduler/src/",
                "scanner-git/src/",
            ],
        ),
        ("12", &["scanner-git/src/"]),
        ("13", &["scanner-scheduler/src/"]),
        (
            "14",
            &[
                "gossip-scanner-runtime/src/",
                "gossip-worker/src/",
                "scanner-rs-cli/src/",
            ],
        ),
    ];

    entries
        .iter()
        .map(|(section, crates)| {
            (
                (*section).to_owned(),
                crates.iter().map(|s| (*s).to_owned()).collect(),
            )
        })
        .collect()
}

/// Parse E-source-file-map.md markdown content into a [`DependencyGraph`].
///
/// Extracts `(source_path, chapter_ids)` pairs from markdown table rows.
/// Rows are recognized by a leading `|` followed by a backtick-wrapped file
/// path containing at least one `/` and ending in a recognized extension
/// (`.rs`, `.md`, `.toml`, `.tla`). Chapter IDs are comma-separated in the
/// second column and follow the `NN-NN` numeric pattern (e.g. `04-11`).
/// Non-numeric chapter references like `Appendix F` or `--` are accepted
/// as-is. Tables with only two columns (no chapter column) are skipped.
pub fn parse_source_file_map(content: &str) -> anyhow::Result<DependencyGraph> {
    let mut source_to_chapters: HashMap<String, Vec<String>> = HashMap::new();
    let mut chapter_to_sources: HashMap<String, Vec<String>> = HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Only process markdown table rows.
        if !trimmed.starts_with('|') {
            continue;
        }

        // Split by `|` and collect non-empty cells.
        let cells: Vec<&str> = trimmed
            .split('|')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        // Skip separator rows (e.g. `|---|---|---|`).
        if cells.iter().all(|c| c.chars().all(|ch| ch == '-')) {
            continue;
        }

        // Need at least 3 columns: file path, chapters, topics.
        // Two-column tables (scanner-git etc.) lack chapter IDs and are skipped.
        if cells.len() < 3 {
            continue;
        }

        let file_cell = cells[0];
        let chapter_cell = cells[1];

        // Strip backticks from the file path.
        let file_path = file_cell.trim_matches('`').trim();

        // Must look like a file path: contains `/` and a recognized extension.
        if !file_path.contains('/') {
            continue;
        }
        if !looks_like_file_path(file_path) {
            continue;
        }

        // Skip header rows that contain column labels.
        let lower = file_path.to_lowercase();
        if lower.contains("source file") || lower.contains("source") && lower.contains("file") {
            continue;
        }

        // Parse comma-separated chapter IDs, stripping whitespace.
        // Valid chapter IDs match the pattern NN-MM (e.g. "02-04", "10-07").
        let chapters: Vec<String> = chapter_cell
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| is_chapter_id(s))
            .collect();

        if chapters.is_empty() {
            continue;
        }

        let path = file_path.to_owned();

        // Build forward map: source -> chapters.
        source_to_chapters
            .entry(path.clone())
            .or_default()
            .extend(chapters.iter().cloned());

        // Build reverse map: chapter -> sources.
        for ch in &chapters {
            chapter_to_sources
                .entry(ch.clone())
                .or_default()
                .push(path.clone());
        }
    }

    // Deduplicate within each map entry (a file can appear in multiple table
    // sections, or a chapter can list the same file twice across rows).
    for chapters in source_to_chapters.values_mut() {
        chapters.sort();
        chapters.dedup();
    }
    for sources in chapter_to_sources.values_mut() {
        sources.sort();
        sources.dedup();
    }

    let section_to_crates = build_section_to_crates();

    Ok(DependencyGraph {
        source_to_chapters,
        chapter_to_sources,
        section_to_crates,
    })
}

/// Heuristic check for whether a string looks like a source file path.
/// Check whether a string looks like a valid chapter ID (`NN-MM` format).
///
/// Accepts IDs like "01-04", "10-07", "14-01". Rejects prose, appendix labels,
/// and other non-chapter text that appears in the source file map tables.
fn is_chapter_id(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let parts: Vec<&str> = s.splitn(2, '-').collect();
    parts.len() == 2
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts[0].chars().all(|c| c.is_ascii_digit())
        && parts[1].chars().all(|c| c.is_ascii_digit())
}

fn looks_like_file_path(s: &str) -> bool {
    let extensions = [".rs", ".md", ".toml", ".tla"];
    extensions.iter().any(|ext| s.ends_with(ext)) || s.contains("/src/") || s.contains("/tests/")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal three-column markdown table for parser testing.
    const SAMPLE_TABLE: &str = r#"
## Identity System

| Source File | Primary Chapters | Topics |
|------------|------------------|---------|
| `crates/gossip-contracts/src/identity/types.rs` | 01-04, 02-04 | Newtype definitions |
| `crates/gossip-contracts/src/identity/canonical.rs` | 01-02, 02-02 | CanonicalBytes trait |
| `crates/gossip-contracts/src/identity/hashing.rs` | 01-01, 01-02, 02-02 | BLAKE3 wrappers |
"#;

    #[test]
    fn parse_extracts_source_to_chapters() {
        let graph = parse_source_file_map(SAMPLE_TABLE).unwrap();

        let types_chapters = graph
            .source_to_chapters
            .get("crates/gossip-contracts/src/identity/types.rs")
            .expect("types.rs should be present");
        assert_eq!(types_chapters, &["01-04", "02-04"]);

        let hashing_chapters = graph
            .source_to_chapters
            .get("crates/gossip-contracts/src/identity/hashing.rs")
            .expect("hashing.rs should be present");
        assert_eq!(hashing_chapters, &["01-01", "01-02", "02-02"]);
    }

    #[test]
    fn parse_builds_reverse_map() {
        let graph = parse_source_file_map(SAMPLE_TABLE).unwrap();

        let ch_01_02 = graph
            .chapter_to_sources
            .get("01-02")
            .expect("chapter 01-02 should be present");

        // Both canonical.rs and hashing.rs reference chapter 01-02.
        assert!(ch_01_02.contains(&"crates/gossip-contracts/src/identity/canonical.rs".to_owned()));
        assert!(ch_01_02.contains(&"crates/gossip-contracts/src/identity/hashing.rs".to_owned()));
    }

    #[test]
    fn maps_are_consistent() {
        let graph = parse_source_file_map(SAMPLE_TABLE).unwrap();

        // Every source in chapter_to_sources must appear in source_to_chapters.
        for sources in graph.chapter_to_sources.values() {
            for src in sources {
                assert!(
                    graph.source_to_chapters.contains_key(src),
                    "source {src} referenced from chapter_to_sources but missing from source_to_chapters",
                );
            }
        }

        // Every chapter in source_to_chapters must appear in chapter_to_sources.
        for chapters in graph.source_to_chapters.values() {
            for ch in chapters {
                assert!(
                    graph.chapter_to_sources.contains_key(ch),
                    "chapter {ch} referenced from source_to_chapters but missing from chapter_to_sources",
                );
            }
        }
    }

    #[test]
    fn roundtrip_serialize_deserialize() {
        let graph = parse_source_file_map(SAMPLE_TABLE).unwrap();

        let dir = std::env::temp_dir().join("fleet_orch_graph_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_graph.json");

        graph.save(&path).unwrap();
        let loaded = DependencyGraph::load(&path).unwrap();

        assert_eq!(graph.source_to_chapters, loaded.source_to_chapters);
        assert_eq!(graph.chapter_to_sources, loaded.chapter_to_sources);
        assert_eq!(graph.section_to_crates, loaded.section_to_crates);

        // Clean up.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn high_degree_sources_filters_by_threshold() {
        let graph = parse_source_file_map(SAMPLE_TABLE).unwrap();

        // hashing.rs has 3 chapters; the others have 2 each.
        let high = graph.high_degree_sources(3);
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].0, "crates/gossip-contracts/src/identity/hashing.rs");
        assert_eq!(high[0].1, 3);

        // Threshold of 2 should return all three files.
        let all = graph.high_degree_sources(2);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn skips_two_column_tables() {
        let two_col = r#"
### scanner-git

| Source File | Topics |
|------------|---------|
| `crates/scanner-git/src/lib.rs` | Crate root |
| `crates/scanner-git/src/runner.rs` | Main scan runner |
"#;
        let graph = parse_source_file_map(two_col).unwrap();

        // Two-column tables lack chapter IDs, so nothing should be extracted.
        assert!(
            graph.source_to_chapters.is_empty(),
            "two-column tables should be skipped"
        );
    }

    #[test]
    fn skips_separator_and_header_rows() {
        let table = r#"
| Source File | Primary Chapters | Topics |
|------------|------------------|---------|
| `crates/gossip-contracts/src/identity/types.rs` | 01-04 | Newtypes |
"#;
        let graph = parse_source_file_map(table).unwrap();

        // Only the data row should be parsed, not the header or separator.
        assert_eq!(graph.source_to_chapters.len(), 1);
        assert!(
            graph
                .source_to_chapters
                .contains_key("crates/gossip-contracts/src/identity/types.rs")
        );
    }

    #[test]
    fn deduplicates_across_sections() {
        let dupe = r#"
| Source File | Primary Chapters | Topics |
|------------|------------------|---------|
| `crates/gossip-contracts/src/identity/coordination.rs` | 02-04, 04-01 | Coordination ids |

## Another section

| Source File | Primary Chapters | Topics |
|------------|------------------|---------|
| `crates/gossip-contracts/src/identity/coordination.rs` | 02-04, 04-01 | Same file again |
"#;
        let graph = parse_source_file_map(dupe).unwrap();

        let chapters = graph
            .source_to_chapters
            .get("crates/gossip-contracts/src/identity/coordination.rs")
            .unwrap();
        // Should be deduplicated despite appearing twice.
        assert_eq!(chapters, &["02-04", "04-01"]);
    }

    #[test]
    fn section_to_crates_has_expected_entries() {
        let graph = parse_source_file_map(SAMPLE_TABLE).unwrap();

        assert!(graph.section_to_crates["00"].is_empty());
        assert_eq!(
            graph.section_to_crates["01"],
            vec!["gossip-contracts/src/identity/"]
        );
        assert!(graph.section_to_crates["04"].contains(&"gossip-coordination/src/".to_owned()));
        assert!(
            graph.section_to_crates["04"].contains(&"gossip-coordination-etcd/src/".to_owned())
        );
    }

    #[test]
    fn rejects_non_numeric_chapter_references() {
        let appendix_table = r#"
| Source File | Primary Chapters | Topics |
|------------|------------------|---------|
| `crates/gossip-stdx/src/lib.rs` | Appendix F | Crate root |
| `crates/gossip-stdx/src/ring_buffer.rs` | Appendix F | Ring buffer |
"#;
        let graph = parse_source_file_map(appendix_table).unwrap();

        // "Appendix F" is not a valid NN-MM chapter ID, so it should be filtered out.
        assert!(graph.chapter_to_sources.is_empty());
        assert!(graph.source_to_chapters.is_empty());
    }

    #[test]
    fn skips_dashes_only_chapter_refs() {
        let dashes_table = r#"
| Source File | Primary Chapters | Topics |
|------------|------------------|---------|
| `crates/gossip-stdx/src/byte_ring.rs` | -- | Byte ring |
"#;
        let graph = parse_source_file_map(dashes_table).unwrap();

        // `--` is not a valid chapter reference; the file should be skipped.
        assert!(graph.source_to_chapters.is_empty());
    }

    #[test]
    fn empty_input_produces_empty_graph() {
        let graph = parse_source_file_map("").unwrap();
        assert!(graph.source_to_chapters.is_empty());
        assert!(graph.chapter_to_sources.is_empty());
        // section_to_crates is always populated from the static mapping.
        assert!(!graph.section_to_crates.is_empty());
    }
}
