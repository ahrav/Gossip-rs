//! Fleet orchestrator entry point.
//!
//! Implements the 5-phase guide-sync pipeline:
//!
//! 0. **Graph + Change Detection** — Build the dependency graph and identify
//!    which source files changed since the last run.
//! 1. **Partition + Launch** — Split affected chapters into disjoint agent
//!    manifests and dispatch them via the Jetty API in waves.
//! 2. **Poll** — Wait for all agents to reach terminal states.
//! 3. **Merge + PR** — Merge agent branches into section integration branches,
//!    consolidate into a single branch, push, and open a pull request.
//! 4. **State Update** — Record which chapters succeeded and persist the
//!    updated fleet state to disk.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;

use fleet_orchestrator::affected::{
    compute_affected_chapters, compute_affected_full, detect_changed_sources, log_bottleneck_report,
};
use fleet_orchestrator::config::FleetConfig;
use fleet_orchestrator::graph::{DependencyGraph, parse_source_file_map};
use fleet_orchestrator::jetty::{JettyClient, JettyConfig};
use fleet_orchestrator::merge::{
    cleanup_worktree, create_merge_worktree, merge_consolidated, merge_section, push_branch,
};
use fleet_orchestrator::partitioner::{self, Tier};
use fleet_orchestrator::pr::{
    PrSummary, TotalStats, create_consolidated_pr, create_section_pr, delete_branches,
};
use fleet_orchestrator::state::{
    AgentResult, AgentStatus, get_guide_sync_state, read_state, set_guide_sync_state,
    update_for_successful_agents, write_state,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Fleet orchestrator for guide-sync.
///
/// Drives dependency-aware parallel documentation builds across a fleet of
/// Jetty workers, merging results back into the target branch.
#[derive(Parser, Debug)]
#[command(name = "fleet-orchestrator", version, about)]
struct Cli {
    /// Perform a dry run: compute the partition plan and exit without
    /// launching agents.
    #[arg(long)]
    dry_run: bool,

    /// Rebuild all chapters regardless of what changed.
    #[arg(long)]
    full: bool,

    /// Restrict the run to a single named section (two-digit prefix).
    #[arg(long)]
    section: Option<String>,

    /// Parallelism tier: 1 (one agent per section), 2 (moderate split),
    /// or 3 (aggressive split).
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(1..=3))]
    tier: u8,
}

// ---------------------------------------------------------------------------
// Type bridging helpers
// ---------------------------------------------------------------------------

/// Convert `affected::AffectedSet` to `partitioner::AffectedSet`.
///
/// The two types are structurally identical but live in separate modules to
/// keep each module's dependency surface minimal.
fn to_partitioner_affected(
    src: &fleet_orchestrator::affected::AffectedSet,
) -> partitioner::AffectedSet {
    partitioner::AffectedSet {
        chapters: src.chapters.clone(),
        by_section: src.by_section.clone(),
    }
}

/// Convert `partitioner::AgentManifest` to `jetty::AgentManifest`.
fn to_jetty_manifest(src: &partitioner::AgentManifest) -> fleet_orchestrator::jetty::AgentManifest {
    fleet_orchestrator::jetty::AgentManifest {
        agent_id: src.agent_id.clone(),
        section: src.section.clone(),
        write_set: src.write_set.clone(),
        read_crates: src.read_crates.clone(),
    }
}

/// Map a `jetty::AgentStatus` to a `state::AgentStatus`.
fn to_state_status(js: &fleet_orchestrator::jetty::AgentStatus) -> AgentStatus {
    match js {
        fleet_orchestrator::jetty::AgentStatus::Completed => AgentStatus::Completed,
        fleet_orchestrator::jetty::AgentStatus::Failed
        | fleet_orchestrator::jetty::AgentStatus::Cancelled
        | fleet_orchestrator::jetty::AgentStatus::Unknown => AgentStatus::Failed,
        fleet_orchestrator::jetty::AgentStatus::Running => AgentStatus::Timeout,
    }
}

// ---------------------------------------------------------------------------
// Git helpers
// ---------------------------------------------------------------------------

/// Get current blob SHAs for all files under `crates/` via `git ls-tree`.
///
/// Returns a map from file path (relative to repo root) to blob SHA. The
/// tree is read from the given `ref_spec` (typically `HEAD` or
/// `origin/main`).
fn get_current_blobs(ref_spec: &str) -> anyhow::Result<HashMap<String, String>> {
    let output = Command::new("git")
        .args(["ls-tree", "-r", ref_spec, "--", "crates/"])
        .output()
        .context("failed to run `git ls-tree`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("`git ls-tree` failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut blobs = HashMap::new();

    for line in stdout.lines() {
        // Format: "<mode> <type> <sha>\t<path>"
        let (meta, path) = match line.split_once('\t') {
            Some(pair) => pair,
            None => continue,
        };
        let sha = meta.split_whitespace().nth(2).unwrap_or("");
        if !sha.is_empty() {
            blobs.insert(path.to_owned(), sha.to_owned());
        }
    }

    Ok(blobs)
}

/// Resolve the SHA of `origin/main`.
fn get_base_sha() -> anyhow::Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "origin/main"])
        .output()
        .context("failed to run `git rev-parse origin/main`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("`git rev-parse origin/main` failed: {stderr}");
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Generate a run ID incorporating the current UTC date and time.
///
/// Format: `guide-sync-YYYY-MM-DD-HHMM`. Uses the system `date` command to
/// avoid pulling in an additional crate dependency.
fn generate_run_id() -> anyhow::Result<String> {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%d-%H%M"])
        .output()
        .context("failed to run `date` for run ID generation")?;

    let stamp = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok(format!("guide-sync-{stamp}"))
}

/// Substitute template variables in the runbook markdown.
///
/// Replaces `{{placeholder}}` tokens with concrete values from the current
/// run configuration and agent manifest.
fn substitute_runbook(
    template: &str,
    manifest: &partitioner::AgentManifest,
    config: &FleetConfig,
    base_sha: &str,
    run_id: &str,
) -> String {
    template
        .replace("{{source_repo}}", &config.source_repo)
        .replace("{{guide_repo}}", &config.guide_repo)
        .replace("{{source_sha}}", base_sha)
        .replace("{{guide_base_branch}}", &config.base_branch)
        .replace("{{agent_id}}", &manifest.agent_id)
        .replace("{{run_id}}", run_id)
        .replace(
            "{{write_set}}",
            &serde_json::to_string(&manifest.write_set).unwrap_or_default(),
        )
        .replace(
            "{{read_crates}}",
            &serde_json::to_string(&manifest.read_crates).unwrap_or_default(),
        )
        .replace("{{section_id}}", &manifest.section)
}

/// Determine the path to the repository root by finding the git toplevel.
fn repo_root() -> anyhow::Result<std::path::PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to run `git rev-parse --show-toplevel`")?;

    if !output.status.success() {
        anyhow::bail!("not inside a git repository");
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok(std::path::PathBuf::from(path))
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    tracing::info!(?cli, "parsed CLI arguments");

    let config = FleetConfig::default();

    // Defer API key check until we actually need it (after dry-run exit point).
    let api_key_lazy = || -> anyhow::Result<String> {
        std::env::var("JETTY_API_KEY").context("JETTY_API_KEY environment variable not set")
    };

    // ======================================================================
    // Phase 0: Dependency Graph + Change Detection
    // ======================================================================

    tracing::info!("Phase 0: building dependency graph and detecting changes");

    let graph = if Path::new(&config.dep_graph_file).exists() && !cli.full {
        tracing::info!(path = %config.dep_graph_file, "loading cached dependency graph");
        DependencyGraph::load(Path::new(&config.dep_graph_file))?
    } else {
        tracing::info!(path = %config.source_file_map, "parsing source file map");
        let map_content = std::fs::read_to_string(&config.source_file_map)
            .with_context(|| format!("read source file map at {}", config.source_file_map))?;
        let g = parse_source_file_map(&map_content)?;

        // Cache the graph for subsequent incremental runs.
        if let Some(parent) = Path::new(&config.dep_graph_file).parent() {
            std::fs::create_dir_all(parent).ok();
        }
        g.save(Path::new(&config.dep_graph_file))?;
        tracing::info!(path = %config.dep_graph_file, "dependency graph saved");
        g
    };

    let base_sha = get_base_sha()?;
    tracing::info!(%base_sha, "resolved origin/main");

    let current_blobs = get_current_blobs(&base_sha)?;
    tracing::info!(files = current_blobs.len(), "read current blob SHAs");

    let state = read_state(Path::new(&config.state_file))?;
    let gs_state = get_guide_sync_state(&state)?;

    let affected = if cli.full {
        tracing::info!("full mode: marking all chapters as affected");
        compute_affected_full(&graph)
    } else {
        let changed = detect_changed_sources(&current_blobs, &gs_state.source_files);
        if changed.is_empty() {
            tracing::info!("no source files changed since last run, nothing to do");
            return Ok(());
        }
        tracing::info!(changed = changed.len(), "source files changed");
        log_bottleneck_report(&changed, &graph);
        compute_affected_chapters(&changed, &graph, &gs_state, &base_sha)
    };

    // Apply --section filter when requested.
    let affected = if let Some(ref section_filter) = cli.section {
        let mut filtered = affected;
        filtered.by_section.retain(|k, _| k == section_filter);
        filtered
            .chapters
            .retain(|ch| ch.split('-').next() == Some(section_filter.as_str()));

        if filtered.chapters.is_empty() {
            tracing::info!(
                section = %section_filter,
                "no affected chapters in the requested section"
            );
            return Ok(());
        }
        tracing::info!(
            section = %section_filter,
            chapters = filtered.chapters.len(),
            "filtered to requested section"
        );
        filtered
    } else {
        affected
    };

    if affected.chapters.is_empty() {
        tracing::info!("no chapters affected, nothing to do");
        return Ok(());
    }

    tracing::info!(
        chapters = affected.chapters.len(),
        sections = affected.by_section.len(),
        "affected chapters computed"
    );

    // ======================================================================
    // Phase 1: Partition + Launch
    // ======================================================================

    tracing::info!("Phase 1: partitioning work and launching agents");

    let tier = match cli.tier {
        1 => Tier::One,
        2 => Tier::Two,
        3 => Tier::Three,
        _ => Tier::One,
    };

    let part_affected = to_partitioner_affected(&affected);
    let manifests = partitioner::partition(&part_affected, tier)?;

    tracing::info!(agents = manifests.len(), "partitioned work into agents");
    for m in &manifests {
        tracing::info!(
            agent = %m.agent_id,
            section = %m.section,
            chapters = m.write_set.len(),
            "agent manifest"
        );
    }

    if cli.dry_run {
        println!("DRY RUN -- partition plan:");
        for m in &manifests {
            println!(
                "  {}: {} chapters in section {}",
                m.agent_id,
                m.write_set.len(),
                m.section
            );
            for ch in &m.write_set {
                println!("    {ch}");
            }
        }
        return Ok(());
    }

    let runbook_template = std::fs::read_to_string(&config.runbook_file)
        .with_context(|| format!("read runbook template at {}", config.runbook_file))?;

    let run_id = generate_run_id()?;
    tracing::info!(%run_id, "generated run ID");

    // Select the effective model for chapter agents. Tier 3 allows routing
    // chapter work to a cheaper mid-tier model while reserving the default
    // (or coordinator_model) for coordinators.
    let chapter_model = if tier == Tier::Three {
        config
            .chapter_agent_model
            .as_deref()
            .unwrap_or(&config.model)
    } else {
        &config.model
    };

    let api_key = api_key_lazy()?;

    let jetty_config = JettyConfig {
        host: config.jetty_host.clone(),
        api_key: api_key.clone(),
        collection: config.jetty_collection.clone(),
        agent: config.agent_type.clone(),
        model: chapter_model.to_owned(),
        timeout_sec: config.timeout_sec,
        task_name: "guide-sync-v2".to_owned(),
    };
    let client = JettyClient::new(jetty_config);

    // Build per-agent runbooks with substituted template variables, and
    // convert manifests to the jetty module's type.
    let jetty_manifests: Vec<fleet_orchestrator::jetty::AgentManifest> =
        manifests.iter().map(to_jetty_manifest).collect();

    // Prepare runbook for the entire batch. Individual agent context is
    // embedded in the user message rather than per-agent system prompts,
    // keeping the launch_wave API simple.
    let runbook = substitute_runbook(
        &runbook_template,
        manifests.first().expect("at least one manifest"),
        &config,
        &base_sha,
        &run_id,
    );

    let trajectory_results = client
        .launch_wave(
            &jetty_manifests,
            &runbook,
            config.wave_size,
            Duration::from_secs(config.wave_delay_sec),
        )
        .await;

    // Separate successful launches from failures.
    let mut trajectories = Vec::new();
    for result in trajectory_results {
        match result {
            Ok(t) => {
                tracing::info!(
                    agent_id = %t.agent_id,
                    trajectory_id = %t.trajectory_id,
                    "agent launched successfully"
                );
                trajectories.push(t);
            }
            Err(e) => {
                tracing::error!("agent launch failed: {e:#}");
            }
        }
    }

    if trajectories.is_empty() {
        anyhow::bail!("all agent launches failed, aborting run");
    }

    tracing::info!(
        launched = trajectories.len(),
        total = manifests.len(),
        "launch phase complete"
    );

    // ======================================================================
    // Phase 2: Poll
    // ======================================================================

    tracing::info!("Phase 2: polling agents until completion");

    let poll_results = client
        .poll_all_until_done(&trajectories, Duration::from_secs(config.poll_timeout_sec))
        .await;

    let mut completed_count = 0u32;
    let mut failed_count = 0u32;
    for (t, status) in &poll_results {
        match status {
            fleet_orchestrator::jetty::AgentStatus::Completed => {
                tracing::info!(agent_id = %t.agent_id, "agent completed");
                completed_count += 1;
            }
            _ => {
                tracing::warn!(agent_id = %t.agent_id, ?status, "agent did not complete");
                failed_count += 1;
            }
        }
    }

    tracing::info!(
        completed = completed_count,
        failed = failed_count,
        "poll phase complete"
    );

    // ======================================================================
    // Phase 2b: Launch + poll coordinator agents (Tier 3 only)
    // ======================================================================
    //
    // In the hierarchical topology each section gets a coordinator agent that
    // merges its chapter-agent branches, validates cross-references, and
    // pushes the section integration branch. Coordinators run AFTER all
    // chapter agents have completed so they can access the pushed branches.

    let mut coordinator_branches: Vec<String> = Vec::new();

    if tier == Tier::Three {
        tracing::info!("Phase 2b: launching section coordinators");

        let coordinator_runbook_template =
            std::fs::read_to_string(&config.coordinator_runbook_file).unwrap_or_default();

        if coordinator_runbook_template.is_empty() {
            tracing::warn!(
                path = %config.coordinator_runbook_file,
                "coordinator runbook is empty or missing, coordinators will receive no system prompt"
            );
        }

        let coordinator_model = config.coordinator_model.as_deref().unwrap_or(&config.model);

        let coordinator_jetty_config = JettyConfig {
            host: config.jetty_host.clone(),
            api_key: api_key.clone(),
            collection: config.jetty_collection.clone(),
            agent: config.agent_type.clone(),
            model: coordinator_model.to_owned(),
            timeout_sec: config.timeout_sec,
            task_name: "guide-sync-v2".to_owned(),
        };
        let coordinator_client = JettyClient::new(coordinator_jetty_config);

        // Build agent-branch names grouped by section for coordinator context.
        let mut agent_branches_by_section: HashMap<String, Vec<String>> = HashMap::new();
        for m in &manifests {
            let branch = format!("guide-sync/{}/{}", m.agent_id, run_id);
            agent_branches_by_section
                .entry(m.section.clone())
                .or_default()
                .push(branch);
        }

        let mut coordinator_trajectories = Vec::new();
        let mut sorted_coord_sections: Vec<&String> = agent_branches_by_section.keys().collect();
        sorted_coord_sections.sort();

        for section_id in &sorted_coord_sections {
            let section_agent_branches = &agent_branches_by_section[*section_id];

            let coord_manifest = fleet_orchestrator::jetty::AgentManifest {
                agent_id: format!("coord-{section_id}"),
                section: (*section_id).clone(),
                write_set: vec![],
                read_crates: vec![],
            };

            let section_chapters_json = serde_json::to_string(
                &affected
                    .by_section
                    .get(*section_id)
                    .cloned()
                    .unwrap_or_default(),
            )
            .unwrap_or_default();

            let coord_runbook = coordinator_runbook_template
                .replace("{{guide_repo}}", &config.guide_repo)
                .replace("{{source_repo}}", &config.source_repo)
                .replace("{{source_sha}}", &base_sha)
                .replace("{{guide_base_branch}}", &config.base_branch)
                .replace("{{section_id}}", section_id)
                .replace("{{run_id}}", &run_id)
                .replace(
                    "{{chapter_agents}}",
                    &serde_json::to_string(section_agent_branches).unwrap_or_default(),
                )
                .replace("{{section_chapters}}", &section_chapters_json);

            let user_msg = format!(
                "Coordinate section '{}': merge {} chapter agent branches, validate cross-references.",
                section_id,
                section_agent_branches.len()
            );

            match coordinator_client
                .launch_agent(&coord_manifest, &coord_runbook, &user_msg)
                .await
            {
                Ok(t) => {
                    tracing::info!(
                        section = %section_id,
                        trajectory = %t.trajectory_id,
                        "coordinator launched"
                    );
                    coordinator_trajectories.push(t);
                }
                Err(e) => {
                    tracing::error!(section = %section_id, "coordinator launch failed: {e:#}");
                }
            }

            // Track coordinator integration branches for cleanup.
            coordinator_branches.push(format!("guide-sync/section-{section_id}/{run_id}"));
        }

        if !coordinator_trajectories.is_empty() {
            tracing::info!(
                count = coordinator_trajectories.len(),
                "polling coordinators"
            );
            let coord_results = coordinator_client
                .poll_all_until_done(
                    &coordinator_trajectories,
                    Duration::from_secs(config.poll_timeout_sec),
                )
                .await;

            let mut coord_completed = 0u32;
            let mut coord_failed = 0u32;
            for (t, status) in &coord_results {
                match status {
                    fleet_orchestrator::jetty::AgentStatus::Completed => {
                        tracing::info!(coord = %t.agent_id, "coordinator completed");
                        coord_completed += 1;
                    }
                    _ => {
                        tracing::warn!(coord = %t.agent_id, ?status, "coordinator did not complete");
                        coord_failed += 1;
                    }
                }
            }

            tracing::info!(
                completed = coord_completed,
                failed = coord_failed,
                "coordinator poll phase complete"
            );
        }
    }

    // ======================================================================
    // Phase 3: Merge + PR
    // ======================================================================

    tracing::info!("Phase 3: merging agent branches and creating PR");

    // Merge happens in the GUIDE repo (where agents push branches), not the
    // source repo. Resolve the guide repo path relative to the source repo root.
    let source_root = repo_root()?;
    let guide_root = source_root
        .parent()
        .map(|p| p.join("gossip-rs-learning-guide"))
        .ok_or_else(|| anyhow::anyhow!("cannot resolve guide repo path from source root"))?;
    anyhow::ensure!(
        guide_root.join(".git").exists(),
        "guide repo not found at {}: clone it first",
        guide_root.display()
    );

    // Fetch latest remote state so agent branches are visible.
    let fetch_output = std::process::Command::new("git")
        .current_dir(&guide_root)
        .args(["fetch", "origin"])
        .output()
        .context("git fetch origin in guide repo")?;
    if !fetch_output.status.success() {
        tracing::warn!(
            "git fetch in guide repo returned non-zero: {}",
            String::from_utf8_lossy(&fetch_output.stderr)
        );
    }

    let worktree = create_merge_worktree(&guide_root, &config.base_branch, &run_id)?;

    // Build agent branch names from manifests: guide-sync/{agent_id}/{run_id}.
    let agent_branches: Vec<String> = manifests
        .iter()
        .map(|m| format!("guide-sync/{}/{}", m.agent_id, run_id))
        .collect();

    // Group branches by section for section-level merges.
    let mut branches_by_section: HashMap<String, Vec<String>> = HashMap::new();
    for (m, branch) in manifests.iter().zip(agent_branches.iter()) {
        branches_by_section
            .entry(m.section.clone())
            .or_default()
            .push(branch.clone());
    }

    let mut section_branches = Vec::new();
    let mut section_merge_results = Vec::new();
    let mut all_agent_branches_to_clean = agent_branches.clone();

    let mut sorted_sections: Vec<&String> = branches_by_section.keys().collect();
    sorted_sections.sort();

    for section_id in sorted_sections {
        let branches = &branches_by_section[section_id];
        let result = merge_section(&worktree, section_id, branches, &run_id)?;

        tracing::info!(
            section = %section_id,
            merged = result.merged.len(),
            conflicts = result.conflicts.len(),
            branch = %result.integration_branch,
            "section merge complete"
        );

        section_branches.push(result.integration_branch.clone());
        all_agent_branches_to_clean.push(result.integration_branch.clone());
        section_merge_results.push((section_id.clone(), result));
    }

    // Include coordinator integration branches in the cleanup set so they
    // are deleted from the remote after PR creation.
    all_agent_branches_to_clean.extend(coordinator_branches);

    // Build PR summaries for each section (used by both consolidated and
    // per-section PR paths).
    let today = run_id
        .strip_prefix("guide-sync-")
        .and_then(|s| s.get(..10))
        .unwrap_or("unknown");

    let pr_summaries: Vec<PrSummary> = section_merge_results
        .iter()
        .map(|(section_id, merge_result)| {
            let section_chapters = affected
                .by_section
                .get(section_id)
                .cloned()
                .unwrap_or_default();

            let trajectory_links: Vec<(String, String)> = poll_results
                .iter()
                .filter(|(t, _)| {
                    manifests
                        .iter()
                        .any(|m| m.agent_id == t.agent_id && &m.section == section_id)
                })
                .map(|(t, _)| {
                    let url = t.workflow_id.as_deref().unwrap_or(&t.trajectory_id);
                    (t.agent_id.clone(), url.to_owned())
                })
                .collect();

            PrSummary {
                section_id: section_id.clone(),
                chapters_updated: section_chapters,
                agents_launched: branches_by_section.get(section_id).map_or(0, |b| b.len()),
                branches_merged: merge_result.merged.len(),
                branches_failed: merge_result.conflicts.clone(),
                verification_notes: String::new(),
                trajectory_links,
                stale_chapters: Vec::new(),
                run_id: run_id.clone(),
                date: today.to_owned(),
            }
        })
        .collect();

    if tier == Tier::One {
        // Tier 1: consolidate all section branches into a single branch and
        // open one PR covering the entire run.
        let consolidated = merge_consolidated(&worktree, &section_branches, &run_id)?;

        tracing::info!(
            merged = consolidated.merged_sections.len(),
            conflicts = consolidated.conflicts.len(),
            branch = %consolidated.consolidated_branch,
            "consolidated merge complete"
        );

        push_branch(&worktree, &consolidated.consolidated_branch)?;
        tracing::info!(
            branch = %consolidated.consolidated_branch,
            "pushed consolidated branch"
        );

        let total_stats = TotalStats {
            total_chapters: pr_summaries.iter().map(|s| s.chapters_updated.len()).sum(),
            total_agents: pr_summaries.iter().map(|s| s.agents_launched).sum(),
            total_merged: pr_summaries.iter().map(|s| s.branches_merged).sum(),
            total_failed: pr_summaries.iter().map(|s| s.branches_failed.len()).sum(),
            total_stale: pr_summaries.iter().map(|s| s.stale_chapters.len()).sum(),
        };

        let pr_result = create_consolidated_pr(
            &config.guide_repo,
            &consolidated.consolidated_branch,
            &config.base_branch,
            &pr_summaries,
            &total_stats,
        );

        match &pr_result {
            Ok(pr) => tracing::info!(url = %pr.url, number = pr.number, "consolidated PR created"),
            Err(e) => tracing::error!("consolidated PR creation failed: {e:#}"),
        }
    } else {
        // Tier 2/3: push each section integration branch and open one PR per
        // section. This keeps reviews scoped to a single documentation section
        // rather than bundling all changes into a monolithic PR.
        let mut pr_urls = Vec::new();
        for (section_id, merge_result) in &section_merge_results {
            if merge_result.merged.is_empty() {
                tracing::warn!(section = %section_id, "no branches merged, skipping PR");
                continue;
            }

            push_branch(&worktree, &merge_result.integration_branch)?;

            let summary = pr_summaries.iter().find(|s| s.section_id == *section_id);
            if let Some(summary) = summary {
                match create_section_pr(
                    &config.guide_repo,
                    section_id,
                    &merge_result.integration_branch,
                    &config.base_branch,
                    summary,
                ) {
                    Ok(pr) => {
                        tracing::info!(section = %section_id, url = %pr.url, "section PR created");
                        pr_urls.push(pr.url);
                    }
                    Err(e) => {
                        tracing::error!(section = %section_id, "section PR failed: {e:#}");
                    }
                }
            }
        }
        tracing::info!(prs_created = pr_urls.len(), "all section PRs created");
    }

    // Clean up the worktree.
    cleanup_worktree(worktree, &guide_root)?;
    tracing::info!("merge worktree cleaned up");

    // Clean up remote branches (best-effort).
    let gh_token = std::env::var("GH_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .unwrap_or_default();

    if !gh_token.is_empty() {
        let deleted =
            delete_branches(&gh_token, &config.guide_repo, &all_agent_branches_to_clean).await?;
        tracing::info!(deleted, "cleaned up remote branches");
    } else {
        tracing::warn!("GH_TOKEN/GITHUB_TOKEN not set, skipping remote branch cleanup");
    }

    // ======================================================================
    // Phase 4: State Update
    // ======================================================================

    tracing::info!("Phase 4: updating fleet state");

    // Build AgentResult entries from poll results and manifest data.
    let agent_results: Vec<AgentResult> = poll_results
        .iter()
        .map(|(trajectory, jetty_status)| {
            let manifest = manifests.iter().find(|m| m.agent_id == trajectory.agent_id);

            let chapters = manifest.map(|m| m.write_set.clone()).unwrap_or_default();

            let is_completed = *jetty_status == fleet_orchestrator::jetty::AgentStatus::Completed;

            // Determine merge success: the agent's branch must appear in the
            // merged list of its section's merge result.
            let branch_name = format!("guide-sync/{}/{}", trajectory.agent_id, run_id);
            let merge_ok = section_merge_results
                .iter()
                .any(|(_, r)| r.merged.contains(&branch_name));

            AgentResult {
                agent_id: trajectory.agent_id.clone(),
                status: to_state_status(jetty_status),
                branch_pushed: is_completed,
                merge_succeeded: is_completed && merge_ok,
                chapters_updated: chapters,
            }
        })
        .collect();

    let state_path = Path::new(&config.state_file);
    let mut fleet_state = read_state(state_path)?;
    let mut gs = get_guide_sync_state(&fleet_state)?;

    update_for_successful_agents(&mut gs, &agent_results, &base_sha, &run_id, &current_blobs);

    set_guide_sync_state(&mut fleet_state, &gs)?;
    write_state(state_path, &fleet_state)?;

    tracing::info!(state_file = %config.state_file, "fleet state persisted");
    tracing::info!("guide-sync run complete");

    Ok(())
}
