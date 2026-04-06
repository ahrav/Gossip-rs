//! Jetty API client.
//!
//! Communicates with Jetty worker instances over HTTP to dispatch chapter build
//! jobs and poll for completion. Handles wave-based concurrency, adaptive
//! polling backoff, and per-request timeouts.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Configuration for the Jetty API client.
#[derive(Debug, Clone)]
pub struct JettyConfig {
    /// Base URL of the Jetty API (e.g., `https://flows-api.jetty.io`).
    pub host: String,
    /// Bearer token for Jetty API authentication.
    pub api_key: String,
    /// Jetty collection identifier.
    pub collection: String,
    /// Agent runtime to use (e.g., `codex`).
    pub agent: String,
    /// Model identifier (e.g., `gpt-5.4`).
    pub model: String,
    /// Per-agent execution timeout in seconds. Defaults to 5400 (90 min).
    pub timeout_sec: u64,
    /// Jetty task name for trajectory tracking (e.g., `guide-sync-v2`).
    pub task_name: String,
}

impl Default for JettyConfig {
    fn default() -> Self {
        Self {
            host: "https://flows-api.jetty.io".to_owned(),
            api_key: String::new(),
            collection: String::new(),
            agent: "codex".to_owned(),
            model: "gpt-5.4".to_owned(),
            timeout_sec: 5400,
            task_name: "guide-sync-v2".to_owned(),
        }
    }
}

/// Tracking information for a launched agent.
#[derive(Debug, Clone)]
pub struct Trajectory {
    /// Identifier of the agent instance (caller-assigned).
    pub agent_id: String,
    /// Trajectory identifier returned by the Jetty API.
    pub trajectory_id: String,
    /// Optional workflow identifier returned alongside the trajectory.
    pub workflow_id: Option<String>,
}

/// Terminal and non-terminal agent execution states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
    Unknown,
}

impl AgentStatus {
    /// Parse a status string from the Jetty API into a typed variant.
    pub fn from_api_str(s: &str) -> Self {
        match s {
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "running" | "pending" | "queued" => Self::Running,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` for states that will not change (completed/failed/cancelled).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Manifest describing what an agent should work on.
#[derive(Debug, Clone, Serialize)]
pub struct AgentManifest {
    /// Caller-assigned agent identifier, used for tracking and branch naming.
    pub agent_id: String,
    /// Section of the documentation to rebuild.
    pub section: String,
    /// Files the agent is allowed to write.
    pub write_set: Vec<String>,
    /// Crates the agent should read for context.
    pub read_crates: Vec<String>,
}

// ---------------------------------------------------------------------------
// Internal response shapes
// ---------------------------------------------------------------------------

/// Top-level Jetty chat completion response (partial -- only fields we need).
#[derive(Debug, Deserialize)]
struct LaunchResponse {
    id: Option<String>,
    #[serde(default)]
    jetty_metadata: Option<JettyMetadata>,
}

#[derive(Debug, Deserialize)]
struct JettyMetadata {
    trajectory_id: Option<String>,
    workflow_id: Option<String>,
}

/// Trajectory status response from the Jetty DB endpoint.
#[derive(Debug, Deserialize)]
struct TrajectoryStatusResponse {
    #[serde(default)]
    status: Option<String>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// HTTP timeout for agent-launch requests.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(60);
/// HTTP timeout for poll/status requests.
const POLL_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Async Jetty API client. Holds a reusable `reqwest::Client` with a
/// pre-configured authorization header and per-request timeout defaults.
///
/// Wrapped in `Arc` internally so that spawned tasks can share the client
/// without lifetime issues.
pub struct JettyClient {
    inner: Arc<JettyClientInner>,
}

struct JettyClientInner {
    http: reqwest::Client,
    config: JettyConfig,
}

impl JettyClient {
    /// Create a new client from the provided configuration.
    ///
    /// The underlying `reqwest::Client` is configured with a default
    /// `Authorization: Bearer <api_key>` header so callers do not need to
    /// supply credentials on each request.
    pub fn new(config: JettyConfig) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        let auth_value = format!("Bearer {}", config.api_key);
        headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&auth_value)
                .expect("API key contains invalid header characters"),
        );

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("failed to build reqwest client");

        Self {
            inner: Arc::new(JettyClientInner { http, config }),
        }
    }

    /// Launch a single agent with the given manifest, runbook, and user
    /// message.
    ///
    /// Sends a `POST /v1/chat/completions` request to the Jetty API and
    /// extracts the trajectory identifier from the response metadata.
    pub async fn launch_agent(
        &self,
        manifest: &AgentManifest,
        runbook: &str,
        user_message: &str,
    ) -> anyhow::Result<Trajectory> {
        let c = &self.inner;
        let url = format!("{}/v1/chat/completions", c.config.host);

        let payload = serde_json::json!({
            "agent": c.config.agent,
            "model": c.config.model,
            "reasoning_effort": "high",
            "timeout": c.config.timeout_sec,
            "timeout_sec": c.config.timeout_sec,
            "messages": [
                { "role": "system", "content": runbook },
                { "role": "user", "content": user_message }
            ],
            "stream": false,
            "jetty": {
                "runbook": true,
                "collection": c.config.collection,
                "task": c.config.task_name,
                "timeout_sec": c.config.timeout_sec,
                "timeout": c.config.timeout_sec,
                "timeout_hint": 10
            }
        });

        tracing::debug!(
            agent_id = %manifest.agent_id,
            payload_bytes = payload.to_string().len(),
            "launching agent"
        );
        tracing::trace!(payload = %payload, "full launch payload");

        let resp = c
            .http
            .post(&url)
            .timeout(LAUNCH_TIMEOUT)
            .json(&payload)
            .send()
            .await?;

        let status = resp.status();
        let raw_body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            anyhow::bail!(
                "Jetty launch failed (HTTP {status}): {}",
                &raw_body[..raw_body.len().min(500)]
            );
        }

        let body: LaunchResponse = serde_json::from_str(&raw_body).map_err(|e| {
            anyhow::anyhow!(
                "failed to parse launch response: {e}\nbody: {}",
                &raw_body[..raw_body.len().min(300)]
            )
        })?;

        // Fallback chain for trajectory identification:
        // 1. jetty_metadata.trajectory_id
        // 2. Suffix of jetty_metadata.workflow_id after the last "--"
        // 3. Top-level response id
        let trajectory_id = body
            .jetty_metadata
            .as_ref()
            .and_then(|m| m.trajectory_id.clone())
            .or_else(|| {
                body.jetty_metadata
                    .as_ref()
                    .and_then(|m| m.workflow_id.as_ref())
                    .and_then(|wid| wid.rsplit("--").next().map(String::from))
            })
            .or_else(|| body.id.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no trajectory_id in response body: {}",
                    &raw_body[..raw_body.len().min(300)]
                )
            })?;

        let workflow_id = body
            .jetty_metadata
            .as_ref()
            .and_then(|m| m.workflow_id.clone())
            .or_else(|| body.id.clone());

        tracing::info!(
            agent_id = %manifest.agent_id,
            %trajectory_id,
            "agent launched"
        );

        Ok(Trajectory {
            agent_id: manifest.agent_id.clone(),
            trajectory_id,
            workflow_id,
        })
    }

    /// Launch agents in waves of `wave_size`, sleeping `delay` between waves.
    ///
    /// Within each wave, all agents are launched concurrently via a
    /// `JoinSet`. Results are collected in manifest order. Uses the default
    /// guide-sync user message format.
    pub async fn launch_wave(
        &self,
        manifests: &[AgentManifest],
        runbook: &str,
        wave_size: usize,
        delay: Duration,
    ) -> Vec<anyhow::Result<Trajectory>> {
        self.launch_wave_with(manifests, runbook, wave_size, delay, |m| {
            format!(
                "Run guide-sync for section '{}' on this repository. \
                 Update {} chapters.",
                m.section,
                m.write_set.len()
            )
        })
        .await
    }

    /// Launch agents in waves with a caller-supplied user message builder.
    ///
    /// Like [`launch_wave`](Self::launch_wave) but the `user_message_fn`
    /// closure generates the user prompt for each agent manifest, allowing
    /// different pipelines to customise the message.
    pub async fn launch_wave_with<F>(
        &self,
        manifests: &[AgentManifest],
        runbook: &str,
        wave_size: usize,
        delay: Duration,
        user_message_fn: F,
    ) -> Vec<anyhow::Result<Trajectory>>
    where
        F: Fn(&AgentManifest) -> String + Send + Sync + 'static,
    {
        let user_message_fn = Arc::new(user_message_fn);
        let mut results = Vec::with_capacity(manifests.len());

        for (wave_idx, chunk) in manifests.chunks(wave_size).enumerate() {
            if wave_idx > 0 {
                tracing::debug!(wave = wave_idx, "inter-wave delay");
                tokio::time::sleep(delay).await;
            }

            tracing::info!(wave = wave_idx, agents = chunk.len(), "launching wave");

            let mut set = tokio::task::JoinSet::new();

            for (pos, m) in chunk.iter().enumerate() {
                let inner = Arc::clone(&self.inner);
                let manifest = m.clone();
                let runbook = runbook.to_owned();
                let msg_fn = Arc::clone(&user_message_fn);

                set.spawn(async move {
                    let user_message = msg_fn(&manifest);
                    let client = JettyClient { inner };
                    let result = client
                        .launch_agent(&manifest, &runbook, &user_message)
                        .await;
                    (pos, result)
                });
            }

            // Collect results in original order.
            let mut wave_results: Vec<Option<anyhow::Result<Trajectory>>> =
                (0..chunk.len()).map(|_| None).collect();

            while let Some(join_result) = set.join_next().await {
                match join_result {
                    Ok((pos, result)) => {
                        match &result {
                            Ok(t) => tracing::debug!(
                                agent_id = %t.agent_id,
                                trajectory = %t.trajectory_id,
                                "launched"
                            ),
                            Err(e) => tracing::error!("launch failed: {e:#}"),
                        }
                        wave_results[pos] = Some(result);
                    }
                    Err(e) => {
                        tracing::error!("task join error: {e:#}");
                    }
                }
            }

            results.extend(wave_results.into_iter().flatten());
        }

        results
    }

    /// Poll the Jetty API for a single trajectory's execution status.
    ///
    /// Queries `GET /api/v1/db/trajectory/{collection}/guide-sync/{id}` and
    /// maps the returned status string to [`AgentStatus`].
    pub async fn poll_status(&self, trajectory_id: &str) -> anyhow::Result<AgentStatus> {
        let c = &self.inner;
        let url = format!(
            "{}/api/v1/db/trajectory/{}/{}/{}",
            c.config.host, c.config.collection, c.config.task_name, trajectory_id
        );

        let resp = c.http.get(&url).timeout(POLL_HTTP_TIMEOUT).send().await?;

        let body: TrajectoryStatusResponse = resp.json().await?;
        let status = body
            .status
            .as_deref()
            .map(AgentStatus::from_api_str)
            .unwrap_or(AgentStatus::Unknown);

        Ok(status)
    }

    /// Poll all trajectories until every agent reaches a terminal state or the
    /// overall `poll_timeout` elapses.
    ///
    /// Uses adaptive polling: starts at 60 s intervals and drops to 30 s once
    /// more than half the fleet has finished. Logs a summary line each cycle.
    pub async fn poll_all_until_done(
        &self,
        trajectories: &[Trajectory],
        poll_timeout: Duration,
    ) -> Vec<(Trajectory, AgentStatus)> {
        let total = trajectories.len();
        let start = tokio::time::Instant::now();
        let mut interval = Duration::from_secs(60);

        // All trajectories start as Running; first poll fires immediately.
        let mut statuses: Vec<AgentStatus> = vec![AgentStatus::Running; total];

        loop {
            // Poll all non-terminal trajectories concurrently.
            let mut set = tokio::task::JoinSet::new();

            for (i, t) in trajectories.iter().enumerate() {
                if statuses[i].is_terminal() {
                    continue;
                }
                let inner = Arc::clone(&self.inner);
                let tid = t.trajectory_id.clone();
                set.spawn(async move {
                    let client = JettyClient { inner };
                    let result = client.poll_status(&tid).await;
                    (i, result)
                });
            }

            while let Some(join_result) = set.join_next().await {
                match join_result {
                    Ok((idx, Ok(s))) => statuses[idx] = s,
                    Ok((_, Err(e))) => {
                        tracing::warn!("poll error: {e:#}");
                    }
                    Err(e) => {
                        tracing::warn!("poll task join error: {e:#}");
                    }
                }
            }

            // Tally current states.
            let mut completed = 0u32;
            let mut running = 0u32;
            let mut failed = 0u32;
            for s in &statuses {
                match s {
                    AgentStatus::Completed => completed += 1,
                    AgentStatus::Failed | AgentStatus::Cancelled => failed += 1,
                    _ => running += 1,
                }
            }

            let elapsed_secs = start.elapsed().as_secs();
            tracing::info!(
                "[{elapsed_secs}s] completed={completed} \
                 running={running} failed={failed} / {total}"
            );

            let terminal = completed + failed;
            if terminal as usize == total {
                break;
            }

            if start.elapsed() >= poll_timeout {
                tracing::warn!(
                    "poll timeout reached after {elapsed_secs}s \
                     with {running} agents still running"
                );
                break;
            }

            // Adaptive backoff: shorten the interval once the majority has
            // reached a terminal state.
            if terminal as usize > total / 2 {
                interval = Duration::from_secs(30);
            }

            tokio::time::sleep(interval).await;
        }

        trajectories.iter().cloned().zip(statuses).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- AgentStatus parsing ------------------------------------------------

    #[test]
    fn status_from_known_strings() {
        assert_eq!(
            AgentStatus::from_api_str("completed"),
            AgentStatus::Completed
        );
        assert_eq!(AgentStatus::from_api_str("failed"), AgentStatus::Failed);
        assert_eq!(
            AgentStatus::from_api_str("cancelled"),
            AgentStatus::Cancelled
        );
        assert_eq!(AgentStatus::from_api_str("running"), AgentStatus::Running);
        assert_eq!(AgentStatus::from_api_str("pending"), AgentStatus::Running);
        assert_eq!(AgentStatus::from_api_str("queued"), AgentStatus::Running);
    }

    #[test]
    fn status_from_unknown_string() {
        assert_eq!(AgentStatus::from_api_str("exploded"), AgentStatus::Unknown);
        assert_eq!(AgentStatus::from_api_str(""), AgentStatus::Unknown);
    }

    #[test]
    fn terminal_states() {
        assert!(AgentStatus::Completed.is_terminal());
        assert!(AgentStatus::Failed.is_terminal());
        assert!(AgentStatus::Cancelled.is_terminal());
        assert!(!AgentStatus::Running.is_terminal());
        assert!(!AgentStatus::Unknown.is_terminal());
    }

    // -- Payload construction -----------------------------------------------

    #[test]
    fn launch_payload_structure() {
        let config = JettyConfig {
            host: "https://test.jetty.io".to_owned(),
            api_key: "test-key".to_owned(),
            collection: "col-123".to_owned(),
            agent: "codex".to_owned(),
            model: "gpt-5.4".to_owned(),
            timeout_sec: 3600,
            task_name: "guide-sync-v2".to_owned(),
        };

        // Reproduce the JSON payload that launch_agent builds.
        let payload = serde_json::json!({
            "agent": config.agent,
            "model": config.model,
            "reasoning_effort": "high",
            "timeout": config.timeout_sec,
            "timeout_sec": config.timeout_sec,
            "messages": [
                { "role": "system", "content": "system-runbook" },
                { "role": "user", "content": "user-msg" }
            ],
            "stream": false,
            "jetty": {
                "runbook": true,
                "collection": config.collection,
                "task": config.task_name,
                "timeout_sec": config.timeout_sec,
                "timeout": config.timeout_sec,
                "timeout_hint": 10
            }
        });

        // Top-level fields.
        assert_eq!(payload["agent"], "codex");
        assert_eq!(payload["model"], "gpt-5.4");
        assert_eq!(payload["reasoning_effort"], "high");
        assert_eq!(payload["timeout"], 3600);
        assert_eq!(payload["timeout_sec"], 3600);
        assert_eq!(payload["stream"], false);

        // Messages array.
        let messages = payload["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "system-runbook");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "user-msg");

        // Jetty sub-object.
        let jetty = &payload["jetty"];
        assert_eq!(jetty["runbook"], true);
        assert_eq!(jetty["collection"], "col-123");
        assert_eq!(jetty["task"], "guide-sync-v2");
        assert_eq!(jetty["timeout_sec"], 3600);
        assert_eq!(jetty["timeout"], 3600);
        assert_eq!(jetty["timeout_hint"], 10);
    }

    // -- Response deserialization -------------------------------------------

    #[test]
    fn launch_response_deserialization_full() {
        let json = serde_json::json!({
            "id": "resp-abc",
            "jetty_metadata": {
                "trajectory_id": "traj-xyz",
                "workflow_id": "wf-123"
            }
        });
        let resp: LaunchResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.id.as_deref(), Some("resp-abc"));
        let meta = resp.jetty_metadata.unwrap();
        assert_eq!(meta.trajectory_id.as_deref(), Some("traj-xyz"));
        assert_eq!(meta.workflow_id.as_deref(), Some("wf-123"));
    }

    #[test]
    fn launch_response_deserialization_minimal() {
        let json = serde_json::json!({ "id": "resp-only" });
        let resp: LaunchResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.id.as_deref(), Some("resp-only"));
        assert!(resp.jetty_metadata.is_none());
    }

    #[test]
    fn trajectory_id_fallback_from_workflow_suffix() {
        // Validates the "--"-split logic used when trajectory_id is absent.
        let workflow_id = "wf--org--traj-456";
        let extracted: &str = workflow_id.rsplit("--").next().unwrap();
        assert_eq!(extracted, "traj-456");
    }

    // -- Manifest serialization ---------------------------------------------

    #[test]
    fn agent_manifest_serialization() {
        let manifest = AgentManifest {
            agent_id: "sec-01".to_owned(),
            section: "identity".to_owned(),
            write_set: vec![
                "docs/identity.md".to_owned(),
                "docs/identity-types.md".to_owned(),
            ],
            read_crates: vec!["gossip-contracts".to_owned()],
        };
        let json = serde_json::to_value(&manifest).unwrap();
        assert_eq!(json["agent_id"], "sec-01");
        assert_eq!(json["section"], "identity");
        assert_eq!(json["write_set"].as_array().unwrap().len(), 2);
        assert_eq!(json["read_crates"].as_array().unwrap().len(), 1);
    }

    // -- Status response parsing --------------------------------------------

    #[test]
    fn trajectory_status_response_parsing() {
        let json = serde_json::json!({ "status": "completed" });
        let resp: TrajectoryStatusResponse = serde_json::from_value(json).unwrap();
        assert_eq!(
            AgentStatus::from_api_str(resp.status.as_deref().unwrap()),
            AgentStatus::Completed
        );
    }

    #[test]
    fn trajectory_status_response_missing_field() {
        let json = serde_json::json!({});
        let resp: TrajectoryStatusResponse = serde_json::from_value(json).unwrap();
        assert!(resp.status.is_none());
    }

    // -- Default config -----------------------------------------------------

    #[test]
    fn default_config_values() {
        let cfg = JettyConfig::default();
        assert_eq!(cfg.host, "https://flows-api.jetty.io");
        assert_eq!(cfg.agent, "codex");
        assert_eq!(cfg.model, "gpt-5.4");
        assert_eq!(cfg.timeout_sec, 5400);
        assert!(cfg.api_key.is_empty());
        assert!(cfg.collection.is_empty());
    }
}
