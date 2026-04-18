//! Configuration.
//!
//! Loads and validates orchestrator settings: Jetty endpoint URLs, parallelism
//! limits, git remote configuration, and section/chapter metadata. Settings
//! can come from a config file, environment variables, or CLI flags.

use serde::{Deserialize, Serialize};

/// Top-level orchestrator configuration.
///
/// Each field has a sensible default suitable for the gossip-rs guide-sync
/// workflow. Values can be overridden via environment variables or a config
/// file in future iterations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    /// Source repository in `owner/repo` format (e.g. `"ahrav/gossip-rs"`).
    pub source_repo: String,
    /// Guide repository in `owner/repo` format.
    pub guide_repo: String,
    /// Base branch name in the guide repository.
    pub base_branch: String,
    /// Jetty API base URL.
    pub jetty_host: String,
    /// Jetty collection identifier.
    pub jetty_collection: String,
    /// Agent runtime type (e.g. `"codex"`).
    pub agent_type: String,
    /// Model identifier passed to the agent runtime.
    pub model: String,
    /// Per-agent execution timeout in seconds.
    pub timeout_sec: u64,
    /// Overall polling timeout in seconds. The orchestrator stops waiting for
    /// agents after this duration even if some are still running.
    pub poll_timeout_sec: u64,
    /// Number of agents to launch concurrently per wave.
    pub wave_size: usize,
    /// Delay in seconds between successive launch waves.
    pub wave_delay_sec: u64,
    /// Path to the fleet state file (JSON).
    pub state_file: String,
    /// Path to the dependency graph cache (JSON).
    pub dep_graph_file: String,
    /// Path to the runbook markdown template.
    pub runbook_file: String,
    /// Path to the coordinator runbook template (Tier 3 only).
    pub coordinator_runbook_file: String,
    /// Path to the E-source-file-map markdown file.
    pub source_file_map: String,
    /// Model override for coordinator agents (Tier 3). Falls back to `model`
    /// when `None`.
    pub coordinator_model: Option<String>,
    /// Model override for chapter agents in Tier 3 mode. Falls back to `model`
    /// when `None`.
    pub chapter_agent_model: Option<String>,
}

impl Default for FleetConfig {
    fn default() -> Self {
        Self {
            source_repo: "ahrav/gossip-rs".to_owned(),
            guide_repo: "ahrav/gossip-rs-learning-guide".to_owned(),
            base_branch: "main".to_owned(),
            jetty_host: "https://flows-api.jetty.io".to_owned(),
            jetty_collection: "asdf22223".to_owned(),
            agent_type: "codex".to_owned(),
            model: "gpt-5.4".to_owned(),
            timeout_sec: 5400,
            poll_timeout_sec: 7200,
            wave_size: 15,
            wave_delay_sec: 2,
            state_file: ".fleet-state.json".to_owned(),
            dep_graph_file: "fleet/dependency_graph.json".to_owned(),
            runbook_file: "runbooks/guide-sync-partitioned.md".to_owned(),
            coordinator_runbook_file: "runbooks/guide-sync-coordinator.md".to_owned(),
            source_file_map: "../gossip-rs-learning-guide/09-appendices/E-source-file-map.md"
                .to_owned(),
            coordinator_model: None,
            chapter_agent_model: None,
        }
    }
}

/// Configuration for the design-doc-audit pipeline.
///
/// Each field has a sensible default sourced from the original
/// `run-audit-fleet.sh` script. The audit pipeline walks `docs/` and
/// `diagrams/` for `.md` files, filters by blob-SHA state, distributes
/// files across agents via round-robin, and merges results into a
/// consolidated PR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Repository in `owner/repo` format (e.g. `"ahrav/gossip-rs"`).
    pub repository: String,
    /// Base branch name.
    pub base_branch: String,
    /// Jetty API base URL.
    pub jetty_host: String,
    /// Jetty collection identifier.
    pub jetty_collection: String,
    /// Agent runtime type.
    pub agent_type: String,
    /// Model identifier passed to the agent runtime.
    pub model: String,
    /// Per-agent execution timeout in seconds.
    pub timeout_sec: u64,
    /// Overall polling timeout in seconds.
    pub poll_timeout_sec: u64,
    /// Number of agents to launch concurrently per wave.
    pub wave_size: usize,
    /// Delay in seconds between successive launch waves.
    pub wave_delay_sec: u64,
    /// Path to the fleet state file (JSON).
    pub state_file: String,
    /// Path to the audit runbook markdown template.
    pub runbook_file: String,
    /// Path to the scope-map TOML that pairs docs with source directories.
    pub scope_map_path: String,
    /// Maximum number of files to process per run.
    pub file_cap: usize,
    /// Maximum number of agents to launch.
    pub agents_cap: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            repository: "ahrav/gossip-rs".to_owned(),
            base_branch: "main".to_owned(),
            jetty_host: "https://flows-api.jetty.io".to_owned(),
            jetty_collection: "asdf22223".to_owned(),
            agent_type: "gemini-cli".to_owned(),
            model: "gemini/gemini-3.1-pro-preview".to_owned(),
            timeout_sec: 5400,
            poll_timeout_sec: 7200,
            wave_size: 15,
            wave_delay_sec: 2,
            state_file: ".fleet-state.json".to_owned(),
            runbook_file: "runbooks/design-doc-audit-partitioned.md".to_owned(),
            scope_map_path: "docs/scope-map.toml".to_owned(),
            file_cap: 40,
            agents_cap: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_are_populated() {
        let cfg = FleetConfig::default();
        assert_eq!(cfg.source_repo, "ahrav/gossip-rs");
        assert_eq!(cfg.guide_repo, "ahrav/gossip-rs-learning-guide");
        assert_eq!(cfg.base_branch, "main");
        assert_eq!(cfg.jetty_host, "https://flows-api.jetty.io");
        assert_eq!(cfg.jetty_collection, "asdf22223");
        assert_eq!(cfg.agent_type, "codex");
        assert_eq!(cfg.model, "gpt-5.4");
        assert_eq!(cfg.timeout_sec, 5400);
        assert_eq!(cfg.poll_timeout_sec, 7200);
        assert_eq!(cfg.wave_size, 15);
        assert_eq!(cfg.wave_delay_sec, 2);
        assert_eq!(cfg.state_file, ".fleet-state.json");
        assert_eq!(cfg.dep_graph_file, "fleet/dependency_graph.json");
        assert_eq!(cfg.runbook_file, "runbooks/guide-sync-partitioned.md");
        assert_eq!(
            cfg.coordinator_runbook_file,
            "runbooks/guide-sync-coordinator.md"
        );
        assert_eq!(
            cfg.source_file_map,
            "../gossip-rs-learning-guide/09-appendices/E-source-file-map.md"
        );
        assert!(cfg.coordinator_model.is_none());
        assert!(cfg.chapter_agent_model.is_none());
    }

    #[test]
    fn roundtrip_serde_json() {
        let cfg = FleetConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let recovered: FleetConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.source_repo, cfg.source_repo);
        assert_eq!(recovered.timeout_sec, cfg.timeout_sec);
        assert_eq!(recovered.wave_size, cfg.wave_size);
        assert_eq!(recovered.coordinator_model, cfg.coordinator_model);
        assert_eq!(recovered.chapter_agent_model, cfg.chapter_agent_model);
        assert_eq!(
            recovered.coordinator_runbook_file,
            cfg.coordinator_runbook_file
        );
    }

    #[test]
    fn roundtrip_serde_json_with_model_overrides() {
        let cfg = FleetConfig {
            coordinator_model: Some("o3-pro".to_owned()),
            chapter_agent_model: Some("gpt-5.4-mini".to_owned()),
            ..FleetConfig::default()
        };

        let json = serde_json::to_string(&cfg).unwrap();
        let recovered: FleetConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.coordinator_model.as_deref(), Some("o3-pro"));
        assert_eq!(
            recovered.chapter_agent_model.as_deref(),
            Some("gpt-5.4-mini")
        );
    }

    #[test]
    fn audit_config_defaults() {
        let cfg = AuditConfig::default();
        assert_eq!(cfg.repository, "ahrav/gossip-rs");
        assert_eq!(cfg.base_branch, "main");
        assert_eq!(cfg.agent_type, "gemini-cli");
        assert_eq!(cfg.model, "gemini/gemini-3.1-pro-preview");
        assert_eq!(cfg.timeout_sec, 5400);
        assert_eq!(cfg.file_cap, 40);
        assert_eq!(cfg.agents_cap, 10);
        assert_eq!(cfg.scope_map_path, "docs/scope-map.toml");
        assert_eq!(cfg.runbook_file, "runbooks/design-doc-audit-partitioned.md");
    }

    #[test]
    fn audit_config_roundtrip_serde_json() {
        let cfg = AuditConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let recovered: AuditConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.repository, cfg.repository);
        assert_eq!(recovered.file_cap, cfg.file_cap);
        assert_eq!(recovered.agents_cap, cfg.agents_cap);
    }
}
