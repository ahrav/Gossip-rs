//! Work partitioning.
//!
//! Divides the set of affected chapters into disjoint write sets suitable for
//! parallel dispatch to agents. Each agent receives exclusive ownership of its
//! assigned chapter files, guaranteeing no two agents write to the same path.
//! Chapters are grouped by section, and the partitioning tier controls how many
//! agents are spawned per section.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An agent's work assignment.
///
/// Each manifest grants exclusive write access to a set of chapter file paths.
/// The `read_crates` field lists source directories the agent should consult
/// for reference material but must not modify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentManifest {
    /// Unique agent identifier (e.g., "sec-04" or "sec-04-a1").
    pub agent_id: String,
    /// Section this agent is assigned to (e.g., "04").
    pub section: String,
    /// Chapter file paths this agent may modify (exclusive write access).
    pub write_set: Vec<String>,
    /// Source crate directories to read for reference.
    pub read_crates: Vec<String>,
}

/// The set of chapters affected by source code changes.
#[derive(Debug, Clone)]
pub struct AffectedSet {
    /// All affected chapter IDs.
    pub chapters: Vec<String>,
    /// Grouped by section: section_id -> chapter_ids.
    pub by_section: HashMap<String, Vec<String>>,
}

/// Partitioning tier configuration.
///
/// Higher tiers create more agents per section, splitting chapters into smaller
/// write sets. This trades coordination overhead for finer-grained parallelism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// 1 agent per section.
    One,
    /// 2-4 agents per large section (roughly 5 chapters each).
    Two,
    /// 5-7 agents per section (roughly 3 chapters each).
    Three,
}

/// Returns source crate directories relevant to a documentation section.
///
/// The mapping is derived from the guide-sync skill's section-to-crate
/// association. Sections without source code dependencies return an empty vec.
fn section_crates(section: &str) -> Vec<String> {
    match section {
        "00" => vec![],
        "01" => vec!["gossip-contracts/src/identity/".into()],
        "02" => vec!["gossip-contracts/src/identity/".into()],
        "03" => vec![],
        "04" => vec![
            "gossip-contracts/src/coordination/".into(),
            "gossip-coordination/src/".into(),
            "gossip-coordination-etcd/src/".into(),
        ],
        "05" => vec!["gossip-frontier/src/".into()],
        "06" => vec![
            "gossip-contracts/src/connector/".into(),
            "gossip-connectors/src/".into(),
            "gossip-scanner-runtime/src/".into(),
        ],
        "07" => vec![
            "gossip-contracts/src/persistence/".into(),
            "gossip-persistence-inmemory/src/".into(),
        ],
        "08" | "09" => vec![],
        "10" => vec!["scanner-engine/src/".into()],
        "11" => vec![
            "gossip-scanner-runtime/src/".into(),
            "scanner-scheduler/src/".into(),
            "scanner-git/src/".into(),
        ],
        "12" => vec!["scanner-git/src/".into()],
        "13" => vec!["scanner-scheduler/src/".into()],
        "14" => vec![
            "gossip-scanner-runtime/src/".into(),
            "gossip-worker/src/".into(),
            "scanner-rs-cli/src/".into(),
        ],
        _ => vec![],
    }
}

/// Extracts the section prefix from a chapter ID.
///
/// Chapter IDs use the format `"SS-CC"` where `SS` is the two-digit section
/// and `CC` is the chapter number within that section. Returns the `"SS"`
/// prefix. Panics if the chapter ID does not contain a `'-'` separator.
pub fn extract_section_from_chapter(chapter_id: &str) -> &str {
    chapter_id
        .split('-')
        .next()
        .expect("chapter ID must contain a '-' separator (e.g. \"02-04\")")
}

/// Partitions affected chapters into disjoint agent manifests.
///
/// Groups chapters by section, then delegates to [`partition_section`] for
/// per-section splitting based on the requested [`Tier`]. Validates that the
/// resulting write sets are disjoint before returning.
pub fn partition(affected: &AffectedSet, tier: Tier) -> anyhow::Result<Vec<AgentManifest>> {
    let mut manifests = Vec::new();

    // Sort section keys for deterministic output ordering.
    let mut sections: Vec<&String> = affected.by_section.keys().collect();
    sections.sort();

    for section in sections {
        let chapters = &affected.by_section[section];
        if chapters.is_empty() {
            continue;
        }
        let section_manifests = partition_section(section, chapters, tier);
        manifests.extend(section_manifests);
    }

    validate_disjoint(&manifests)?;
    Ok(manifests)
}

/// Splits a single section's chapters across one or more agents.
///
/// The number of agents depends on the tier:
/// - [`Tier::One`]: a single agent owns all chapters.
/// - [`Tier::Two`]: chapters are split round-robin across `ceil(len/5)` agents,
///   capped at 4.
/// - [`Tier::Three`]: chapters are split round-robin across `ceil(len/3)` agents,
///   capped at 7.
///
/// When only one agent is produced, its ID is `"sec-{section}"`. Otherwise
/// agents are numbered `"sec-{section}-a1"`, `"sec-{section}-a2"`, etc.
pub fn partition_section(section: &str, chapters: &[String], tier: Tier) -> Vec<AgentManifest> {
    if chapters.is_empty() {
        return Vec::new();
    }

    let agent_count = match tier {
        Tier::One => 1,
        Tier::Two => {
            let raw = chapters.len().div_ceil(5);
            raw.clamp(1, 4)
        }
        Tier::Three => {
            let raw = chapters.len().div_ceil(3);
            raw.clamp(1, 7)
        }
    };

    let read_crates = section_crates(section);

    if agent_count == 1 {
        return vec![AgentManifest {
            agent_id: format!("sec-{section}"),
            section: section.to_string(),
            write_set: chapters.to_vec(),
            read_crates,
        }];
    }

    // Distribute chapters round-robin across agents.
    let mut buckets: Vec<Vec<String>> = vec![Vec::new(); agent_count];
    for (i, chapter) in chapters.iter().enumerate() {
        buckets[i % agent_count].push(chapter.clone());
    }

    buckets
        .into_iter()
        .enumerate()
        .filter(|(_, bucket)| !bucket.is_empty())
        .map(|(idx, bucket)| AgentManifest {
            agent_id: format!("sec-{section}-a{}", idx + 1),
            section: section.to_string(),
            write_set: bucket,
            read_crates: read_crates.clone(),
        })
        .collect()
}

/// Validates that no chapter appears in more than one manifest's write set.
///
/// Returns `Ok(())` when all write sets are disjoint. Returns an error listing
/// every duplicated chapter and the conflicting agent IDs.
pub fn validate_disjoint(manifests: &[AgentManifest]) -> anyhow::Result<()> {
    let mut seen: HashMap<&str, &str> = HashMap::new();
    let mut conflicts: Vec<String> = Vec::new();

    for manifest in manifests {
        for chapter in &manifest.write_set {
            if let Some(&previous_agent) = seen.get(chapter.as_str()) {
                conflicts.push(format!(
                    "chapter {chapter:?} assigned to both {previous_agent:?} and {:?}",
                    manifest.agent_id
                ));
            } else {
                seen.insert(chapter.as_str(), &manifest.agent_id);
            }
        }
    }

    if conflicts.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("write set overlap detected:\n  {}", conflicts.join("\n  "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an `AffectedSet` from a flat list of chapter IDs.
    fn make_affected(chapter_ids: &[&str]) -> AffectedSet {
        let chapters: Vec<String> = chapter_ids.iter().map(|s| (*s).to_string()).collect();
        let mut by_section: HashMap<String, Vec<String>> = HashMap::new();
        for ch in &chapters {
            let section = extract_section_from_chapter(ch).to_string();
            by_section.entry(section).or_default().push(ch.clone());
        }
        AffectedSet {
            chapters,
            by_section,
        }
    }

    #[test]
    fn tier_one_groups_by_section() {
        let affected = make_affected(&[
            "01-01", "01-02", "01-03", "01-04", "01-05", "04-01", "04-02", "04-03", "04-04",
            "04-05", "07-01", "07-02", "07-03", "07-04",
        ]);

        let manifests = partition(&affected, Tier::One).unwrap();
        assert_eq!(manifests.len(), 3, "3 sections -> 3 manifests at Tier::One");

        // Verify each manifest owns all chapters for its section.
        for m in &manifests {
            let expected = affected.by_section.get(&m.section).unwrap();
            assert_eq!(&m.write_set, expected);
        }
    }

    #[test]
    fn tier_two_splits_large_section() {
        let chapters: Vec<String> = (1..=14).map(|i| format!("04-{i:02}")).collect();
        let manifests = partition_section("04", &chapters, Tier::Two);

        // ceil(14/5) = 3, capped at 4 -> 3 agents.
        assert_eq!(manifests.len(), 3);

        let total: usize = manifests.iter().map(|m| m.write_set.len()).sum();
        assert_eq!(total, 14, "all chapters must be assigned");

        // Verify round-robin distribution: 5, 5, 4.
        assert_eq!(manifests[0].write_set.len(), 5);
        assert_eq!(manifests[1].write_set.len(), 5);
        assert_eq!(manifests[2].write_set.len(), 4);
    }

    #[test]
    fn tier_three_splits_large_section() {
        let chapters: Vec<String> = (1..=14).map(|i| format!("04-{i:02}")).collect();
        let manifests = partition_section("04", &chapters, Tier::Three);

        // ceil(14/3) = 5, capped at 7 -> 5 agents.
        assert_eq!(manifests.len(), 5);

        let total: usize = manifests.iter().map(|m| m.write_set.len()).sum();
        assert_eq!(total, 14, "all chapters must be assigned");

        // Verify round-robin distribution: 3, 3, 3, 3, 2.
        assert_eq!(manifests[0].write_set.len(), 3);
        assert_eq!(manifests[1].write_set.len(), 3);
        assert_eq!(manifests[2].write_set.len(), 3);
        assert_eq!(manifests[3].write_set.len(), 3);
        assert_eq!(manifests[4].write_set.len(), 2);
    }

    #[test]
    fn empty_section_produces_no_manifests() {
        let affected = AffectedSet {
            chapters: Vec::new(),
            by_section: HashMap::new(),
        };
        let manifests = partition(&affected, Tier::One).unwrap();
        assert!(manifests.is_empty());
    }

    #[test]
    fn empty_chapter_list_for_section() {
        let manifests = partition_section("04", &[], Tier::One);
        assert!(manifests.is_empty());
    }

    #[test]
    fn disjoint_validation_catches_overlap() {
        let m1 = AgentManifest {
            agent_id: "sec-04-a1".into(),
            section: "04".into(),
            write_set: vec!["04-01".into(), "04-02".into()],
            read_crates: vec![],
        };
        let m2 = AgentManifest {
            agent_id: "sec-04-a2".into(),
            section: "04".into(),
            write_set: vec!["04-02".into(), "04-03".into()],
            read_crates: vec![],
        };

        let err = validate_disjoint(&[m1, m2]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("04-02"),
            "error should name the overlapping chapter"
        );
        assert!(
            msg.contains("sec-04-a1"),
            "error should name the first agent"
        );
        assert!(
            msg.contains("sec-04-a2"),
            "error should name the second agent"
        );
    }

    #[test]
    fn disjoint_validation_passes_clean_manifests() {
        let m1 = AgentManifest {
            agent_id: "sec-04-a1".into(),
            section: "04".into(),
            write_set: vec!["04-01".into(), "04-02".into()],
            read_crates: vec![],
        };
        let m2 = AgentManifest {
            agent_id: "sec-04-a2".into(),
            section: "04".into(),
            write_set: vec!["04-03".into(), "04-04".into()],
            read_crates: vec![],
        };

        validate_disjoint(&[m1, m2]).expect("disjoint sets should pass validation");
    }

    #[test]
    fn single_agent_naming() {
        let manifests = partition_section("04", &["04-01".into()], Tier::One);
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].agent_id, "sec-04");
    }

    #[test]
    fn multi_agent_naming() {
        let chapters: Vec<String> = (1..=10).map(|i| format!("04-{i:02}")).collect();
        let manifests = partition_section("04", &chapters, Tier::Two);

        assert!(manifests.len() > 1);
        for (i, m) in manifests.iter().enumerate() {
            assert_eq!(m.agent_id, format!("sec-04-a{}", i + 1));
        }
    }

    #[test]
    fn read_crates_populated_from_section_map() {
        let manifests = partition_section("04", &["04-01".into()], Tier::One);
        assert_eq!(manifests[0].read_crates.len(), 3);
        assert!(
            manifests[0]
                .read_crates
                .contains(&"gossip-coordination/src/".to_string())
        );
    }

    #[test]
    fn section_with_no_crates() {
        let manifests = partition_section("00", &["00-01".into()], Tier::One);
        assert!(manifests[0].read_crates.is_empty());
    }

    #[test]
    fn extract_section() {
        assert_eq!(extract_section_from_chapter("02-04"), "02");
        assert_eq!(extract_section_from_chapter("14-01"), "14");
    }

    #[test]
    fn tier_two_small_section_single_agent() {
        // 4 chapters: ceil(4/5) = 1 -> single agent.
        let chapters: Vec<String> = (1..=4).map(|i| format!("01-{i:02}")).collect();
        let manifests = partition_section("01", &chapters, Tier::Two);
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].agent_id, "sec-01");
        assert_eq!(manifests[0].write_set.len(), 4);
    }

    #[test]
    fn tier_three_small_section_single_agent() {
        // 2 chapters: ceil(2/3) = 1 -> single agent.
        let chapters: Vec<String> = (1..=2).map(|i| format!("01-{i:02}")).collect();
        let manifests = partition_section("01", &chapters, Tier::Three);
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].agent_id, "sec-01");
        assert_eq!(manifests[0].write_set.len(), 2);
    }

    #[test]
    fn tier2_section_with_6_chapters() {
        // ceil(6/5) = 2 agents, round-robin yields 3 chapters each.
        let chapters: Vec<String> = (1..=6).map(|i| format!("04-{i:02}")).collect();
        let manifests = partition_section("04", &chapters, Tier::Two);

        assert_eq!(manifests.len(), 2);
        assert_eq!(manifests[0].write_set.len(), 3);
        assert_eq!(manifests[1].write_set.len(), 3);

        let total: usize = manifests.iter().map(|m| m.write_set.len()).sum();
        assert_eq!(total, 6);
    }

    #[test]
    fn tier2_section_with_14_chapters() {
        // ceil(14/5) = 3, under cap of 4 -> 3 agents.
        let chapters: Vec<String> = (1..=14).map(|i| format!("07-{i:02}")).collect();
        let manifests = partition_section("07", &chapters, Tier::Two);

        assert_eq!(manifests.len(), 3);

        let total: usize = manifests.iter().map(|m| m.write_set.len()).sum();
        assert_eq!(total, 14);

        // Round-robin: 5, 5, 4.
        assert_eq!(manifests[0].write_set.len(), 5);
        assert_eq!(manifests[1].write_set.len(), 5);
        assert_eq!(manifests[2].write_set.len(), 4);
    }

    #[test]
    fn tier3_section_with_14_chapters() {
        // ceil(14/3) = 5, under cap of 7 -> 5 agents.
        let chapters: Vec<String> = (1..=14).map(|i| format!("07-{i:02}")).collect();
        let manifests = partition_section("07", &chapters, Tier::Three);

        assert_eq!(manifests.len(), 5);

        let total: usize = manifests.iter().map(|m| m.write_set.len()).sum();
        assert_eq!(total, 14);

        // Round-robin: 3, 3, 3, 3, 2.
        assert_eq!(manifests[0].write_set.len(), 3);
        assert_eq!(manifests[1].write_set.len(), 3);
        assert_eq!(manifests[2].write_set.len(), 3);
        assert_eq!(manifests[3].write_set.len(), 3);
        assert_eq!(manifests[4].write_set.len(), 2);
    }

    #[test]
    fn tier2_small_section_stays_single() {
        // 3 chapters: ceil(3/5) = 1 -> single agent even at Tier::Two.
        let chapters: Vec<String> = (1..=3).map(|i| format!("02-{i:02}")).collect();
        let manifests = partition_section("02", &chapters, Tier::Two);

        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].agent_id, "sec-02");
        assert_eq!(manifests[0].write_set.len(), 3);
    }

    #[test]
    fn tier2_full_partition_multiple_sections() {
        // Section 01: 3 chapters -> 1 agent (ceil(3/5)=1).
        // Section 04: 8 chapters -> 2 agents (ceil(8/5)=2).
        // Section 07: 12 chapters -> 3 agents (ceil(12/5)=3).
        // Total: 6 agents.
        let mut ids: Vec<&str> = Vec::new();
        let sec01: Vec<&str> = vec!["01-01", "01-02", "01-03"];
        let sec04: Vec<&str> = vec![
            "04-01", "04-02", "04-03", "04-04", "04-05", "04-06", "04-07", "04-08",
        ];
        let sec07: Vec<&str> = vec![
            "07-01", "07-02", "07-03", "07-04", "07-05", "07-06", "07-07", "07-08", "07-09",
            "07-10", "07-11", "07-12",
        ];
        ids.extend_from_slice(&sec01);
        ids.extend_from_slice(&sec04);
        ids.extend_from_slice(&sec07);

        let affected = make_affected(&ids);
        let manifests = partition(&affected, Tier::Two).unwrap();

        assert_eq!(manifests.len(), 6, "1 + 2 + 3 = 6 agents across 3 sections");

        // Every chapter assigned exactly once (disjoint invariant already
        // validated inside partition, but verify total count explicitly).
        let total: usize = manifests.iter().map(|m| m.write_set.len()).sum();
        assert_eq!(total, ids.len());
    }

    #[test]
    fn tier3_cap_at_7() {
        // 25 chapters: ceil(25/3) = 9, capped at 7.
        let chapters: Vec<String> = (1..=25).map(|i| format!("04-{i:02}")).collect();
        let manifests = partition_section("04", &chapters, Tier::Three);

        assert_eq!(manifests.len(), 7, "must cap at 7, not ceil(25/3)=9");

        let total: usize = manifests.iter().map(|m| m.write_set.len()).sum();
        assert_eq!(total, 25);

        // Round-robin across 7 buckets: 4, 4, 4, 4, 3, 3, 3.
        let mut sizes: Vec<usize> = manifests.iter().map(|m| m.write_set.len()).collect();
        sizes.sort_unstable();
        sizes.reverse();
        assert_eq!(sizes, vec![4, 4, 4, 4, 3, 3, 3]);
    }
}
