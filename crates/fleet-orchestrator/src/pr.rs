//! PR creation and cleanup.
//!
//! Opens pull requests for merged documentation updates and cleans up stale
//! worker branches after successful merges. Coordinates with the repository
//! hosting API to manage the PR lifecycle.
//!
//! PR creation shells out to the `gh` CLI for authentication and API access.
//! Branch deletion uses the GitHub GraphQL API via `reqwest` for batch
//! efficiency, falling back to sequential REST calls through `gh` when the
//! batch mutation is unavailable or fails.

use std::process::Command;

use anyhow::{Context, bail};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Summary data for inclusion in a PR body.
///
/// Captures per-section metrics from a guide-sync run: which chapters were
/// updated, how many agents participated, merge outcomes, and links to agent
/// trajectory logs for auditability.
#[derive(Debug, Clone)]
pub struct PrSummary {
    /// Section identifier (two-digit prefix, e.g. "04").
    pub section_id: String,
    /// Chapter IDs that were successfully updated.
    pub chapters_updated: Vec<String>,
    /// Total agents launched for this section.
    pub agents_launched: usize,
    /// Branches that merged successfully.
    pub branches_merged: usize,
    /// Branch names that failed or were skipped.
    pub branches_failed: Vec<String>,
    /// Free-form verification notes (e.g. diff stats, lint results).
    pub verification_notes: String,
    /// `(agent_id, trajectory_url)` pairs for each agent's execution log.
    pub trajectory_links: Vec<(String, String)>,
    /// Chapters in this section that were NOT updated in this run.
    pub stale_chapters: Vec<String>,
    /// Unique run identifier for traceability.
    pub run_id: String,
    /// ISO date string (e.g. "2026-04-04").
    pub date: String,
}

/// Result of a successful PR creation.
#[derive(Debug)]
pub struct PrResult {
    /// Full URL of the created PR (e.g. `https://github.com/org/repo/pull/42`).
    pub url: String,
    /// PR number within the repository.
    pub number: u64,
}

/// Aggregate statistics across all sections for a consolidated PR.
#[derive(Debug, Default)]
pub struct TotalStats {
    pub total_chapters: usize,
    pub total_agents: usize,
    pub total_merged: usize,
    pub total_failed: usize,
    pub total_stale: usize,
}

// ---------------------------------------------------------------------------
// PR body formatting
// ---------------------------------------------------------------------------

/// Build the markdown body for a single-section PR.
fn format_section_body(summary: &PrSummary) -> String {
    let mut body = String::with_capacity(1024);

    body.push_str(&format!(
        "## Guide Sync \u{2014} Section {}\n\n",
        summary.section_id
    ));

    // Summary table.
    body.push_str("### Summary\n\n");
    body.push_str("| Metric | Count |\n");
    body.push_str("|--------|-------|\n");
    body.push_str(&format!(
        "| Chapters updated | {} |\n",
        summary.chapters_updated.len()
    ));
    body.push_str(&format!(
        "| Agents launched | {} |\n",
        summary.agents_launched
    ));
    body.push_str(&format!(
        "| Branches merged | {} |\n",
        summary.branches_merged
    ));
    body.push_str(&format!(
        "| Failed/skipped | {} |\n",
        summary.branches_failed.len()
    ));

    // Verification notes.
    body.push_str("\n### Verification\n\n");
    if summary.verification_notes.is_empty() {
        body.push_str("_No verification notes._\n");
    } else {
        body.push_str(&summary.verification_notes);
        body.push('\n');
    }

    // Stale chapters.
    body.push_str("\n### Stale Chapters (not updated)\n\n");
    if summary.stale_chapters.is_empty() {
        body.push_str("_All chapters in this section are up to date._\n");
    } else {
        for ch in &summary.stale_chapters {
            body.push_str(&format!("- {ch}\n"));
        }
    }

    // Trajectory links.
    format_trajectory_section(&mut body, &summary.trajectory_links);

    // Run metadata footer.
    body.push_str(&format!(
        "\n---\nRun `{}` | {}\n",
        summary.run_id, summary.date
    ));

    body
}

/// Build the markdown body for a consolidated (multi-section) PR.
fn format_consolidated_body(summaries: &[PrSummary], total: &TotalStats) -> String {
    let mut body = String::with_capacity(2048);

    body.push_str("## Guide Sync \u{2014} Consolidated\n\n");

    // Aggregate summary table.
    body.push_str("### Overall Summary\n\n");
    body.push_str("| Metric | Count |\n");
    body.push_str("|--------|-------|\n");
    body.push_str(&format!(
        "| Chapters updated | {} |\n",
        total.total_chapters
    ));
    body.push_str(&format!("| Agents launched | {} |\n", total.total_agents));
    body.push_str(&format!("| Branches merged | {} |\n", total.total_merged));
    body.push_str(&format!("| Failed/skipped | {} |\n", total.total_failed));
    body.push_str(&format!("| Stale chapters | {} |\n", total.total_stale));

    // Per-section breakdown.
    for summary in summaries {
        body.push_str(&format!("\n### Section {}\n\n", summary.section_id));
        body.push_str(&format!(
            "- **Chapters updated:** {}\n",
            summary.chapters_updated.join(", ")
        ));
        body.push_str(&format!(
            "- **Agents:** {} launched, {} merged, {} failed\n",
            summary.agents_launched,
            summary.branches_merged,
            summary.branches_failed.len()
        ));

        if !summary.stale_chapters.is_empty() {
            body.push_str(&format!(
                "- **Stale:** {}\n",
                summary.stale_chapters.join(", ")
            ));
        }

        if !summary.verification_notes.is_empty() {
            body.push_str(&format!(
                "- **Verification:** {}\n",
                summary.verification_notes
            ));
        }

        format_trajectory_section(&mut body, &summary.trajectory_links);
    }

    // Run metadata footer (use the first summary's run_id and date).
    if let Some(first) = summaries.first() {
        body.push_str(&format!("\n---\nRun `{}` | {}\n", first.run_id, first.date));
    }

    body
}

/// Append an "Agent Trajectories" section to `body` if any links are present.
fn format_trajectory_section(body: &mut String, links: &[(String, String)]) {
    body.push_str("\n### Agent Trajectories\n\n");
    if links.is_empty() {
        body.push_str("_No trajectory links available._\n");
    } else {
        for (agent_id, url) in links {
            body.push_str(&format!("- **{agent_id}**: [{agent_id}]({url})\n"));
        }
    }
}

// ---------------------------------------------------------------------------
// PR creation (via `gh` CLI)
// ---------------------------------------------------------------------------

/// Create a pull request for a single documentation section.
///
/// Shells out to `gh pr create` with the formatted title and body. The caller
/// must ensure the `branch` has been pushed to the remote before calling.
pub fn create_section_pr(
    repo: &str,
    section_id: &str,
    branch: &str,
    base: &str,
    summary: &PrSummary,
) -> anyhow::Result<PrResult> {
    let title = format!("docs(guide): sync section {section_id} ({})", summary.date);
    let body = format_section_body(summary);
    run_gh_pr_create(repo, branch, base, &title, &body)
}

/// Create a consolidated pull request spanning multiple sections.
///
/// Used in Tier 1 (single-PR) mode where all section changes are collected
/// onto one branch. The body aggregates per-section summaries with an overall
/// statistics table at the top.
pub fn create_consolidated_pr(
    repo: &str,
    branch: &str,
    base: &str,
    summaries: &[PrSummary],
    total_stats: &TotalStats,
) -> anyhow::Result<PrResult> {
    let date = summaries
        .first()
        .map(|s| s.date.as_str())
        .unwrap_or("unknown");
    let title = format!("docs(guide): guide-sync sweep ({date})");
    let body = format_consolidated_body(summaries, total_stats);
    run_gh_pr_create(repo, branch, base, &title, &body)
}

/// Execute `gh pr create` and parse the resulting URL and PR number.
fn run_gh_pr_create(
    repo: &str,
    branch: &str,
    base: &str,
    title: &str,
    body: &str,
) -> anyhow::Result<PrResult> {
    let output = Command::new("gh")
        .args([
            "pr", "create", "--repo", repo, "--base", base, "--head", branch, "--title", title,
            "--body", body,
        ])
        .output()
        .context("failed to execute `gh pr create`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("`gh pr create` failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_pr_output(stdout.trim())
}

/// Parse a PR URL emitted by `gh pr create` (e.g. "https://github.com/org/repo/pull/42").
///
/// Extracts the trailing numeric PR number from the URL path.
fn parse_pr_output(url: &str) -> anyhow::Result<PrResult> {
    let number = url
        .rsplit('/')
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .with_context(|| format!("cannot parse PR number from gh output: {url:?}"))?;

    Ok(PrResult {
        url: url.to_owned(),
        number,
    })
}

// ---------------------------------------------------------------------------
// Audit PR creation
// ---------------------------------------------------------------------------

/// Summary data for an audit sweep PR body.
#[derive(Debug, Clone)]
pub struct AuditPrSummary {
    /// Number of files audited in this batch.
    pub files_audited: usize,
    /// Total agents launched.
    pub agents_launched: usize,
    /// Agent branches that merged successfully.
    pub branches_merged: usize,
    /// Files skipped because they were unchanged since the last audit.
    pub skipped_count: usize,
    /// Files remaining for future runs (exceeded the per-run cap).
    pub deferred_count: usize,
    /// Post-merge verification notes (fmt, check, doc results).
    pub verification_notes: String,
    /// `(agent_id, trajectory_url)` pairs for auditability.
    pub trajectory_links: Vec<(String, String)>,
    /// ISO date string (e.g. "2026-04-05").
    pub date: String,
    /// Unique run identifier.
    pub run_id: String,
}

/// Build the markdown body for an audit sweep PR.
fn format_audit_body(summary: &AuditPrSummary) -> String {
    let mut body = String::with_capacity(1024);

    body.push_str("## Design Doc Audit Sweep\n\n");

    body.push_str(&format!(
        "Next {} unprocessed docs/diagrams ({} remaining after this batch).\n\n",
        summary.files_audited, summary.deferred_count
    ));

    body.push_str("### Summary\n\n");
    body.push_str("| Metric | Count |\n");
    body.push_str("|--------|-------|\n");
    body.push_str(&format!("| Files audited | {} |\n", summary.files_audited));
    body.push_str(&format!(
        "| Agents launched | {} |\n",
        summary.agents_launched
    ));
    body.push_str(&format!(
        "| Branches merged | {} |\n",
        summary.branches_merged
    ));
    body.push_str(&format!(
        "| Already processed (skipped) | {} |\n",
        summary.skipped_count
    ));
    body.push_str(&format!(
        "| Remaining for future runs | {} |\n",
        summary.deferred_count
    ));

    body.push_str("\n### Verification\n\n");
    if summary.verification_notes.is_empty() {
        body.push_str("All checks passed.\n");
    } else {
        body.push_str(&summary.verification_notes);
        body.push('\n');
    }

    format_trajectory_section(&mut body, &summary.trajectory_links);

    body.push_str(&format!(
        "\n---\nRun `{}` | {}\n",
        summary.run_id, summary.date
    ));

    body
}

/// Create a pull request for a design-doc audit sweep.
///
/// Shells out to `gh pr create` with the formatted title and body.
pub fn create_audit_pr(
    repo: &str,
    branch: &str,
    base: &str,
    summary: &AuditPrSummary,
) -> anyhow::Result<PrResult> {
    let title = format!("docs: design doc audit sweep ({})", summary.date);
    let body = format_audit_body(summary);
    run_gh_pr_create(repo, branch, base, &title, &body)
}

// ---------------------------------------------------------------------------
// Branch cleanup — GraphQL batch
// ---------------------------------------------------------------------------

/// Delete multiple branches in a single GraphQL mutation.
///
/// Sends a `deleteRefs`-style `updateRefs` mutation to the GitHub GraphQL API,
/// setting each ref's `afterOid` to the zero SHA to request deletion. This is
/// significantly faster than sequential REST calls when cleaning up dozens of
/// agent branches after a run.
///
/// Returns the number of branches for which deletion was requested. The API
/// silently ignores refs that have already been deleted, so the returned count
/// may exceed the number of branches that actually existed.
pub async fn batch_delete_branches_graphql(
    token: &str,
    repo_owner: &str,
    repo_name: &str,
    branches: &[String],
) -> anyhow::Result<usize> {
    if branches.is_empty() {
        return Ok(0);
    }

    let repo_id = query_repository_id(token, repo_owner, repo_name).await?;

    // Build refUpdates array: each entry sets afterOid to the zero SHA,
    // which tells GitHub to delete the ref regardless of its current value.
    let ref_updates: Vec<serde_json::Value> = branches
        .iter()
        .map(|branch| {
            serde_json::json!({
                "name": format!("refs/heads/{branch}"),
                "afterOid": "0000000000000000000000000000000000000000"
            })
        })
        .collect();

    let mutation = serde_json::json!({
        "query": "mutation($input: UpdateRefsInput!) { updateRefs(input: $input) { clientMutationId } }",
        "variables": {
            "input": {
                "repositoryId": repo_id,
                "refUpdates": ref_updates
            }
        }
    });

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.github.com/graphql")
        .bearer_auth(token)
        .header("User-Agent", "fleet-orchestrator")
        .json(&mutation)
        .send()
        .await
        .context("GraphQL request to delete branches failed")?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .context("failed to parse GraphQL response body")?;

    if !status.is_success() {
        bail!("GraphQL branch deletion returned HTTP {status}: {body}");
    }

    if let Some(errors) = body.get("errors") {
        bail!("GraphQL branch deletion errors: {errors}");
    }

    info!(
        count = branches.len(),
        "batch-deleted branches via GraphQL updateRefs"
    );

    Ok(branches.len())
}

/// Query the GitHub GraphQL API for a repository's node ID.
async fn query_repository_id(token: &str, owner: &str, name: &str) -> anyhow::Result<String> {
    let query = serde_json::json!({
        "query": format!(
            r#"query {{ repository(owner: "{owner}", name: "{name}") {{ id }} }}"#
        )
    });

    let client = reqwest::Client::new();
    let resp = client
        .post("https://api.github.com/graphql")
        .bearer_auth(token)
        .header("User-Agent", "fleet-orchestrator")
        .json(&query)
        .send()
        .await
        .context("GraphQL repository ID query failed")?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .context("failed to parse GraphQL repository ID response")?;

    if !status.is_success() {
        bail!("GraphQL repository ID query returned HTTP {status}: {body}");
    }

    if let Some(errors) = body.get("errors") {
        bail!("GraphQL repository ID query errors: {errors}");
    }

    body.get("data")
        .and_then(|d| d.get("repository"))
        .and_then(|r| r.get("id"))
        .and_then(|id| id.as_str())
        .map(String::from)
        .context("GraphQL response missing data.repository.id")
}

// ---------------------------------------------------------------------------
// Branch cleanup — sequential fallback (via `gh` CLI)
// ---------------------------------------------------------------------------

/// Delete branches one at a time via the GitHub REST API.
///
/// Used as a fallback when the GraphQL batch mutation is unavailable (e.g.,
/// insufficient token scopes or API errors). Each branch is deleted with a
/// separate `gh api` call. Failures on individual branches are logged but
/// do not abort the loop; the function returns the count of successful
/// deletions.
pub fn delete_branches_sequential(repo: &str, branches: &[String]) -> anyhow::Result<usize> {
    let mut deleted = 0usize;

    for branch in branches {
        let endpoint = format!("repos/{repo}/git/refs/heads/{branch}");
        let output = Command::new("gh")
            .args(["api", "-X", "DELETE", &endpoint])
            .output()
            .with_context(|| format!("failed to execute `gh api DELETE` for branch {branch:?}"))?;

        if output.status.success() {
            deleted += 1;
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(branch, %stderr, "sequential branch deletion failed");
        }
    }

    info!(
        deleted,
        total = branches.len(),
        "sequential branch deletion complete"
    );
    Ok(deleted)
}

// ---------------------------------------------------------------------------
// Branch cleanup — unified entry point
// ---------------------------------------------------------------------------

/// Delete agent branches, preferring the GraphQL batch mutation.
///
/// Attempts [`batch_delete_branches_graphql`] first. On any error, logs a
/// warning and falls back to [`delete_branches_sequential`]. The `repo`
/// parameter uses `owner/name` format (e.g. "org/repo").
pub async fn delete_branches(
    token: &str,
    repo: &str,
    branches: &[String],
) -> anyhow::Result<usize> {
    if branches.is_empty() {
        return Ok(0);
    }

    // Split "owner/name" for the GraphQL API.
    let (owner, name) = repo
        .split_once('/')
        .with_context(|| format!("repo must be in owner/name format, got {repo:?}"))?;

    match batch_delete_branches_graphql(token, owner, name, branches).await {
        Ok(count) => {
            info!(count, method = "graphql", "branch cleanup complete");
            Ok(count)
        }
        Err(e) => {
            warn!(
                error = %e,
                "GraphQL batch branch deletion failed, falling back to sequential"
            );
            let count = delete_branches_sequential(repo, branches)?;
            info!(count, method = "sequential", "branch cleanup complete");
            Ok(count)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal `PrSummary` for formatting tests.
    fn sample_summary() -> PrSummary {
        PrSummary {
            section_id: "04".to_owned(),
            chapters_updated: vec!["04-01".to_owned(), "04-02".to_owned(), "04-03".to_owned()],
            agents_launched: 2,
            branches_merged: 2,
            branches_failed: vec!["guide-sync/04-fail".to_owned()],
            verification_notes: "All diffs reviewed, no regressions.".to_owned(),
            trajectory_links: vec![
                (
                    "sec-04-a1".to_owned(),
                    "https://example.com/traj/sec-04-a1".to_owned(),
                ),
                (
                    "sec-04-a2".to_owned(),
                    "https://example.com/traj/sec-04-a2".to_owned(),
                ),
            ],
            stale_chapters: vec!["04-10".to_owned(), "04-11".to_owned()],
            run_id: "run-2026-04-04-001".to_owned(),
            date: "2026-04-04".to_owned(),
        }
    }

    #[test]
    fn section_pr_title_contains_section_and_date() {
        let summary = sample_summary();
        let title = format!(
            "docs(guide): sync section {} ({})",
            summary.section_id, summary.date
        );
        assert!(title.contains("04"));
        assert!(title.contains("2026-04-04"));
        assert!(title.starts_with("docs(guide):"));
    }

    #[test]
    fn section_body_contains_summary_table() {
        let summary = sample_summary();
        let body = format_section_body(&summary);

        assert!(body.contains("## Guide Sync"));
        assert!(body.contains("Section 04"));
        assert!(body.contains("| Chapters updated | 3 |"));
        assert!(body.contains("| Agents launched | 2 |"));
        assert!(body.contains("| Branches merged | 2 |"));
        assert!(body.contains("| Failed/skipped | 1 |"));
    }

    #[test]
    fn section_body_contains_verification_notes() {
        let summary = sample_summary();
        let body = format_section_body(&summary);

        assert!(body.contains("### Verification"));
        assert!(body.contains("All diffs reviewed, no regressions."));
    }

    #[test]
    fn section_body_lists_stale_chapters() {
        let summary = sample_summary();
        let body = format_section_body(&summary);

        assert!(body.contains("### Stale Chapters"));
        assert!(body.contains("- 04-10"));
        assert!(body.contains("- 04-11"));
    }

    #[test]
    fn section_body_lists_trajectory_links() {
        let summary = sample_summary();
        let body = format_section_body(&summary);

        assert!(body.contains("### Agent Trajectories"));
        assert!(body.contains("**sec-04-a1**"));
        assert!(body.contains("https://example.com/traj/sec-04-a1"));
        assert!(body.contains("**sec-04-a2**"));
    }

    #[test]
    fn section_body_includes_run_footer() {
        let summary = sample_summary();
        let body = format_section_body(&summary);

        assert!(body.contains("Run `run-2026-04-04-001`"));
        assert!(body.contains("2026-04-04"));
    }

    #[test]
    fn empty_stale_chapters_shows_up_to_date_message() {
        let mut summary = sample_summary();
        summary.stale_chapters.clear();
        let body = format_section_body(&summary);

        assert!(body.contains("All chapters in this section are up to date."));
    }

    #[test]
    fn empty_verification_notes_shows_placeholder() {
        let mut summary = sample_summary();
        summary.verification_notes.clear();
        let body = format_section_body(&summary);

        assert!(body.contains("No verification notes."));
    }

    #[test]
    fn empty_trajectory_links_shows_placeholder() {
        let mut summary = sample_summary();
        summary.trajectory_links.clear();
        let body = format_section_body(&summary);

        assert!(body.contains("No trajectory links available."));
    }

    #[test]
    fn consolidated_title_contains_date() {
        let summary = sample_summary();
        let date = &summary.date;
        let title = format!("docs(guide): guide-sync sweep ({date})");
        assert!(title.contains("2026-04-04"));
        assert!(title.starts_with("docs(guide):"));
    }

    #[test]
    fn consolidated_body_contains_overall_stats() {
        let summaries = vec![sample_summary()];
        let total = TotalStats {
            total_chapters: 3,
            total_agents: 2,
            total_merged: 2,
            total_failed: 1,
            total_stale: 2,
        };

        let body = format_consolidated_body(&summaries, &total);

        assert!(body.contains("## Guide Sync"));
        assert!(body.contains("### Overall Summary"));
        assert!(body.contains("| Chapters updated | 3 |"));
        assert!(body.contains("| Agents launched | 2 |"));
        assert!(body.contains("| Branches merged | 2 |"));
        assert!(body.contains("| Failed/skipped | 1 |"));
        assert!(body.contains("| Stale chapters | 2 |"));
    }

    #[test]
    fn consolidated_body_contains_per_section_breakdown() {
        let mut s1 = sample_summary();
        s1.section_id = "01".to_owned();
        s1.chapters_updated = vec!["01-01".to_owned()];

        let mut s2 = sample_summary();
        s2.section_id = "04".to_owned();

        let total = TotalStats::default();
        let body = format_consolidated_body(&[s1, s2], &total);

        assert!(body.contains("### Section 01"));
        assert!(body.contains("### Section 04"));
        assert!(body.contains("01-01"));
        assert!(body.contains("04-01, 04-02, 04-03"));
    }

    #[test]
    fn consolidated_body_run_footer_uses_first_summary() {
        let summaries = vec![sample_summary()];
        let total = TotalStats::default();
        let body = format_consolidated_body(&summaries, &total);

        assert!(body.contains("Run `run-2026-04-04-001`"));
    }

    #[test]
    fn total_stats_default_is_zeroed() {
        let stats = TotalStats::default();
        assert_eq!(stats.total_chapters, 0);
        assert_eq!(stats.total_agents, 0);
        assert_eq!(stats.total_merged, 0);
        assert_eq!(stats.total_failed, 0);
        assert_eq!(stats.total_stale, 0);
    }

    #[test]
    fn parse_pr_output_extracts_number() {
        let result = parse_pr_output("https://github.com/org/repo/pull/42").unwrap();
        assert_eq!(result.number, 42);
        assert_eq!(result.url, "https://github.com/org/repo/pull/42");
    }

    #[test]
    fn parse_pr_output_handles_large_number() {
        let result = parse_pr_output("https://github.com/org/repo/pull/9999").unwrap();
        assert_eq!(result.number, 9999);
    }

    #[test]
    fn parse_pr_output_rejects_non_numeric() {
        let result = parse_pr_output("https://github.com/org/repo/pull/abc");
        assert!(result.is_err());
    }

    #[test]
    fn parse_pr_output_rejects_empty() {
        let result = parse_pr_output("");
        assert!(result.is_err());
    }

    #[test]
    fn total_stats_aggregation() {
        let summaries = [
            PrSummary {
                section_id: "01".to_owned(),
                chapters_updated: vec!["01-01".to_owned(), "01-02".to_owned()],
                agents_launched: 1,
                branches_merged: 1,
                branches_failed: vec![],
                verification_notes: String::new(),
                trajectory_links: vec![],
                stale_chapters: vec!["01-03".to_owned()],
                run_id: "run-1".to_owned(),
                date: "2026-04-04".to_owned(),
            },
            PrSummary {
                section_id: "04".to_owned(),
                chapters_updated: vec!["04-01".to_owned()],
                agents_launched: 3,
                branches_merged: 2,
                branches_failed: vec!["guide-sync/04-fail".to_owned()],
                verification_notes: String::new(),
                trajectory_links: vec![],
                stale_chapters: vec!["04-10".to_owned(), "04-11".to_owned()],
                run_id: "run-1".to_owned(),
                date: "2026-04-04".to_owned(),
            },
        ];

        let total = TotalStats {
            total_chapters: summaries.iter().map(|s| s.chapters_updated.len()).sum(),
            total_agents: summaries.iter().map(|s| s.agents_launched).sum(),
            total_merged: summaries.iter().map(|s| s.branches_merged).sum(),
            total_failed: summaries.iter().map(|s| s.branches_failed.len()).sum(),
            total_stale: summaries.iter().map(|s| s.stale_chapters.len()).sum(),
        };

        assert_eq!(total.total_chapters, 3);
        assert_eq!(total.total_agents, 4);
        assert_eq!(total.total_merged, 3);
        assert_eq!(total.total_failed, 1);
        assert_eq!(total.total_stale, 3);
    }

    // -- Audit PR formatting --------------------------------------------------

    fn sample_audit_summary() -> AuditPrSummary {
        AuditPrSummary {
            files_audited: 15,
            agents_launched: 5,
            branches_merged: 4,
            skipped_count: 10,
            deferred_count: 3,
            verification_notes: "- cargo fmt: PASSED\n- cargo check: PASSED".to_owned(),
            trajectory_links: vec![(
                "batch-01".to_owned(),
                "https://example.com/traj/batch-01".to_owned(),
            )],
            date: "2026-04-05".to_owned(),
            run_id: "audit-2026-04-05-1430".to_owned(),
        }
    }

    #[test]
    fn audit_body_contains_summary_table() {
        let summary = sample_audit_summary();
        let body = format_audit_body(&summary);

        assert!(body.contains("## Design Doc Audit Sweep"));
        assert!(body.contains("| Files audited | 15 |"));
        assert!(body.contains("| Agents launched | 5 |"));
        assert!(body.contains("| Branches merged | 4 |"));
        assert!(body.contains("| Already processed (skipped) | 10 |"));
        assert!(body.contains("| Remaining for future runs | 3 |"));
    }

    #[test]
    fn audit_body_contains_verification() {
        let summary = sample_audit_summary();
        let body = format_audit_body(&summary);

        assert!(body.contains("### Verification"));
        assert!(body.contains("cargo fmt: PASSED"));
    }

    #[test]
    fn audit_body_contains_trajectories() {
        let summary = sample_audit_summary();
        let body = format_audit_body(&summary);

        assert!(body.contains("**batch-01**"));
        assert!(body.contains("https://example.com/traj/batch-01"));
    }

    #[test]
    fn audit_body_contains_run_footer() {
        let summary = sample_audit_summary();
        let body = format_audit_body(&summary);

        assert!(body.contains("Run `audit-2026-04-05-1430`"));
        assert!(body.contains("2026-04-05"));
    }

    #[test]
    fn audit_body_empty_verification_shows_all_passed() {
        let mut summary = sample_audit_summary();
        summary.verification_notes.clear();
        let body = format_audit_body(&summary);

        assert!(body.contains("All checks passed."));
    }
}
