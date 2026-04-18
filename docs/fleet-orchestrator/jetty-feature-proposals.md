# Jetty Feature Proposals for Fleet Orchestration

Proposals born from building and operating a 20-100 agent fleet orchestrator
for guide-sync. Each proposal identifies the pain point it solves, the current
workaround, and the proposed Jetty-native solution.

---

## Tier 1: High-Impact, Practical Wins

### 1. Shared Artifact Store

**Pain point**: Agents push branches to GitHub and the orchestrator fetches
them back. GitHub is a rate-limited, high-latency intermediary for what is
really just "pass files between agents."

**Current workaround**: Each agent pushes a branch to GitHub. The orchestrator
creates a git worktree, fetches every agent branch, merges locally, and pushes
the result. At 100 agents this burns hundreds of GitHub API calls and 3-8
minutes of merge time.

**Proposal**: A fleet-scoped blob store keyed by `{run_id}/{agent_id}/{path}`
where agents write outputs and other agents or the orchestrator read them.

```
CURRENT:
  Agent A --push--> GitHub --fetch--> Orchestrator --fetch--> Agent B

WITH ARTIFACT STORE:
  Agent A --put--> /fleet/{run_id}/sec-04-a1/ --get--> Agent B
                                                 |
                                    Orchestrator --get-->
```

**API sketch**:
```bash
# Agent writes an artifact
curl -X PUT "$JETTY_HOST/v1/fleet/$RUN_ID/artifacts/sec-04-a1/chapter-04-01.md" \
  --data-binary @chapter-04-01.md

# Coordinator reads chapter agent artifacts
curl "$JETTY_HOST/v1/fleet/$RUN_ID/artifacts?prefix=sec-04-"

# Orchestrator downloads final merged result
curl "$JETTY_HOST/v1/fleet/$RUN_ID/artifacts/coord-04/section-04.tar.gz" -o section-04.tar.gz
```

**What it eliminates**:
- GitHub branch push/fetch for inter-agent data transfer
- GitHub API rate limit pressure (80 content-generating requests/minute)
- 5-30 seconds per agent for branch push
- The entire merge worktree workflow when combined with built-in merge

---

### 2. Webhook / Callback on Completion

**Pain point**: The orchestrator polls every 30-60 seconds, burning thousands of
API requests over a 90-minute run. At 100 agents with 30-second polling, that is
12,000 requests per hour — 2.4x over GitHub's primary rate limit (though polling
hits Jetty, not GitHub).

**Current workaround**: Adaptive polling with backoff (60s initial, 30s after
50% completion). This reduces but does not eliminate the waste.

**Proposal**: Push-based completion notification via webhook or WebSocket.

**Option A — Webhook callback**:
```json
{
  "jetty": {
    "on_complete": {
      "url": "https://my-server/hooks/fleet",
      "metadata": {"run_id": "guide-sync-v2-2026-04-05"}
    }
  }
}
```

**Option B — WebSocket event stream**:
```
ws://flows-api.jetty.io/v1/fleet/{run_id}/events

Events:
  {"type": "agent_started",   "agent_id": "sec-04-a1", "timestamp": "..."}
  {"type": "agent_completed", "agent_id": "sec-04-a1", "trajectory_id": "abc123"}
  {"type": "agent_failed",    "agent_id": "sec-04-a2", "error": "timeout"}
  {"type": "fleet_done",      "completed": 18, "failed": 2}
```

**What it eliminates**:
- The entire polling loop (Phase 2)
- Thousands of wasted HTTP requests
- 30-60 second latency between agent completion and orchestrator reaction

---

### 3. Agent Chaining / DAG Workflows

**Pain point**: The orchestrator must manage multi-phase sequencing. Chapter
agents run first, the orchestrator waits for all to complete, then launches
coordinators. This requires the orchestrator to stay alive for the entire run
and implement phase transitions.

**Current workaround**: Phase 2a polls chapter agents, Phase 2b launches
coordinators after all chapter agents complete. The orchestrator is a
long-running state machine.

**Proposal**: Declare agent dependencies at launch time. Jetty holds dependent
agents in a queue and auto-launches them when their dependencies resolve.

```json
{
  "jetty": {
    "task": "guide-sync-v2",
    "agent_id": "coord-04",
    "depends_on": ["sec-04-a1", "sec-04-a2", "sec-04-a3"],
    "trigger": "all_completed"
  }
}
```

The orchestrator launches everything upfront (chapter agents + coordinators in
one batch) and Jetty sequences them internally.

**Trigger modes**:
- `all_completed` — launch when every dependency finishes successfully
- `any_completed` — launch when the first dependency finishes (fan-in race)
- `all_terminal` — launch when all dependencies reach a terminal state
  (completed or failed), useful for coordinators that handle partial failure

**What it eliminates**:
- Phase 2b orchestration logic entirely
- The orchestrator needing to stay alive between phases
- Multi-round API calls (launch, poll, launch again, poll again)

---

### 4. Fleet-Scoped Shared State

**Pain point**: Agents have no way to share ephemeral coordination state during
a run. The orchestrator tracks per-agent status in local memory and writes
persistent state to `.fleet-state.json` after the run.

**Current workaround**: The orchestrator polls Jetty for agent status and
maintains an in-memory map of results. Coordinators have no visibility into
chapter agent outputs until they fetch branches from GitHub.

**Proposal**: A key-value store scoped to the fleet run, readable and writable
by all agents in the fleet.

```bash
# Agent writes its status
curl -X PUT "$JETTY_HOST/v1/fleet/$RUN_ID/state/sec-04-a1" \
  -d '{"chapters_updated": ["04-01", "04-06"], "findings": 3, "status": "done"}'

# Coordinator reads chapter agent statuses
curl "$JETTY_HOST/v1/fleet/$RUN_ID/state?prefix=sec-04-"

# Orchestrator reads aggregate state
curl "$JETTY_HOST/v1/fleet/$RUN_ID/state"
```

**What it eliminates**:
- Custom in-memory status tracking in the orchestrator
- The need for agents to push branches just to signal completion
- Coordinators guessing which chapter agents succeeded

---

## Tier 2: Architecture-Changing Features

### 5. Shared Repository Snapshot

**Pain point**: Every agent clones the source repository independently. With 20
agents, that is 20 redundant downloads of the same ~200MB repository.

**Current workaround**: Each agent runs `gh repo clone` in its sandbox. Clone
time is 5-30 seconds depending on repo size and network conditions.

**Proposal**: Jetty maintains a pre-warmed, content-addressed repository cache.
Agents request a snapshot at a specific SHA and receive an instant read-only
mount.

```json
{
  "jetty": {
    "repo_snapshots": {
      "source": {
        "repo": "ahrav/gossip-rs",
        "ref": "abc123def456",
        "mount": "/workspace/source",
        "mode": "read_only"
      },
      "guide": {
        "repo": "ahrav/gossip-rs-learning-guide",
        "ref": "main",
        "mount": "/workspace/guide",
        "mode": "copy_on_write"
      }
    }
  }
}
```

Implementation: snapshot the repo once per unique `(repo, ref)` pair, mount
into sandboxes via copy-on-write filesystem (overlayfs or similar). The write
layer is per-agent for isolation.

**What it eliminates**:
- N redundant clones (saves N x 5-30 seconds)
- Network bandwidth for large repositories
- Agent startup latency (clone is often the longest setup step)

---

### 6. Agent-to-Agent Messaging

**Pain point**: Agents operate in total isolation. When one agent discovers
information relevant to other agents (a type was renamed, a module was deleted),
there is no way to communicate this. Other agents independently discover the
same thing or, worse, produce inconsistent fixes.

**Current workaround**: Disjoint write sets prevent merge conflicts, but
semantic inconsistencies (agentic drift) pass through git merge undetected.
Coordinators catch some of these post-hoc, but only within a single section.

**Proposal**: A pub/sub message bus scoped to the fleet run.

```bash
# Agent A discovers a rename and broadcasts it
jetty-msg publish --topic="sec-04" --type="rename" \
  '{"old": "ShardSpec", "new": "ShardDescriptor", "files": ["04-01.md", "04-07.md"]}'

# Agent B subscribes and adapts its chapter edits
jetty-msg subscribe --topic="sec-04" --filter="type=rename" --callback="handle_rename"

# Cross-section broadcast for codebase-wide changes
jetty-msg publish --topic="global" --type="crate_removed" \
  '{"crate": "gossip-legacy", "replacement": "gossip-stdx"}'
```

**Use cases**:
- Chapter agent discovers a type rename, broadcasts to all section agents
- Coordinator sends "re-check line 47" to a chapter agent for targeted fix
- Agent discovers a removed crate, broadcasts globally so all sections update
- Agents negotiate overlapping cross-references in real time

**What it eliminates**:
- Agentic drift (the number one failure mode from research, F10)
- Redundant discovery across agents
- Post-hoc cross-reference validation by coordinators

---

### 7. Built-in Merge Service

**Pain point**: The orchestrator implements its own merge infrastructure: git
worktree creation, sequential branch fetching, three-way merge with conflict
abort, branch push, and worktree cleanup. This is ~200 lines of code in
`merge.rs` that reimplements what Jetty could do natively.

**Current workaround**: `merge.rs` creates a temporary git worktree, fetches
each agent branch, merges sequentially, pushes the result, and cleans up.

**Proposal**: Jetty provides a merge endpoint that combines agent outputs
server-side.

```json
POST /v1/fleet/{run_id}/merge
{
  "sources": ["sec-04-a1", "sec-04-a2", "sec-04-a3"],
  "target_repo": "ahrav/gossip-rs-learning-guide",
  "target_branch": "guide-sync/section-04/{run_id}",
  "strategy": "sequential",
  "on_conflict": "skip_and_report"
}
```

Response:
```json
{
  "status": "completed",
  "merged": ["sec-04-a1", "sec-04-a2", "sec-04-a3"],
  "conflicts": [],
  "branch": "guide-sync/section-04/guide-sync-2026-04-05-1430",
  "commit_sha": "def456..."
}
```

**What it eliminates**:
- `merge.rs` entirely (~200 lines)
- Git worktree management
- GitHub rate limits for branch operations (Jetty uses its own token)
- Network round-trips between local machine and GitHub for merge operations

---

## Tier 3: Paradigm Shifts

### 8. Fleet Templates

**Pain point**: The entire orchestrator binary (`fleet-orchestrator`, ~650 lines
of Rust across 9 modules) implements a pattern that is common across fleet
workloads: fan-out, poll, fan-in, merge, report. Every fleet operator rebuilds
this from scratch.

**Current workaround**: A custom Rust binary with tokio, reqwest, petgraph, and
git subprocess calls.

**Proposal**: Define fleet topologies declaratively. Jetty becomes the
orchestrator.

```yaml
fleet: guide-sync
topology: fan-out-coordinate-merge

config:
  source_repo: ahrav/gossip-rs
  guide_repo: ahrav/gossip-rs-learning-guide
  state_file: .fleet-state.json

tiers:
  1:
    partition: by_section
    agents_per_section: 1
    pr: consolidated
  2:
    partition: by_chapter
    agents_per_section: max_4
    pr: per_section
  3:
    partition: by_chapter
    agents_per_section: max_7
    coordinators: true
    pr: per_section

stages:
  - name: chapter-agents
    runbook: runbooks/guide-sync-partitioned.md
    partition: "{tier.partition}"

  - name: coordinators
    runbook: runbooks/guide-sync-coordinator.md
    depends_on: chapter-agents
    partition: by_section
    condition: "tier >= 3"

  - name: merge
    type: builtin/merge
    depends_on: [chapter-agents, coordinators]
    target_repo: "{config.guide_repo}"

  - name: pr
    type: builtin/create-pr
    depends_on: merge
    template: section-pr
```

Launch:
```bash
jetty fleet run guide-sync --tier=3 --full
```

**What it eliminates**:
- The entire orchestrator binary
- Custom partitioning, polling, merge, and PR code
- The need for Rust/tokio/reqwest dependencies
- Per-fleet reimplementation of the same fan-out/fan-in pattern

---

### 9. Speculative Execution

**Pain point**: Phases are strictly sequential. Coordinators wait for ALL
chapter agents to finish before starting. If 18 of 20 agents are done but 2
are slow, the coordinators sit idle for 30+ minutes.

**Current workaround**: None. The orchestrator blocks until all chapter agents
reach terminal state.

**Proposal**: Launch downstream agents speculatively before all upstream
dependencies complete. Speculative agents begin work on available inputs and
do a final reconciliation pass when the last dependency resolves.

```
CURRENT (sequential):
  |--- chapter agents (60 min) ---|--- coordinators (15 min) ---|
  Total: 75 min

SPECULATIVE:
  |--- chapter agents (60 min) ---|
  |------- coordinators start at 40 min, final merge at 60 min ---|
  Total: ~62 min
```

Coordinators begin cross-reference analysis on the 18 completed chapters while
2 are still running. When the last chapter agent completes, the coordinator does
a final incremental merge pass. If a chapter agent fails, the coordinator
discards speculative work for that chapter.

```json
{
  "jetty": {
    "depends_on": ["sec-04-a1", "sec-04-a2", "sec-04-a3"],
    "trigger": "speculative",
    "speculative_threshold": 0.8
  }
}
```

Starts when 80% of dependencies are complete; reconciles on 100%.

**What it eliminates**:
- 15-30 minutes of idle wall-clock time per run
- Strict sequential phase boundaries

---

### 10. Live Agent Observatory

**Pain point**: During a 90-minute run, the orchestrator has no visibility into
what agents are actually doing. It knows "running" or "completed" but not
progress, token usage, or what files are being modified.

**Current workaround**: Check the Jetty web UI manually. No structured
real-time data.

**Proposal**: A real-time dashboard and API for fleet observability.

```
https://flows.jetty.io/asdf22223/guide-sync-v2/fleet/guide-sync-2026-04-05

FLEET: guide-sync-2026-04-05    STATUS: 18/20 chapter agents done
ELAPSED: 47m    TOKENS: 1.2M    EST. COST: $4.80

+-- sec-00     [DONE]    12k tok  3/3 chaps  1 finding   32s
+-- sec-01-a1  [DONE]    18k tok  2/2 chaps  0 findings  45s
+-- sec-01-a2  [DONE]    15k tok  2/2 chaps  2 findings  41s
+-- sec-04-a1  [RUNNING] 47k tok  2/3 chaps  3 findings  ...
+-- sec-04-a2  [RUNNING] 31k tok  1/3 chaps  0 findings  ...
+-- sec-04-a3  [DONE]    52k tok  3/3 chaps  4 findings  89s
+-- coord-04   [QUEUED]  waiting on sec-04-a1, sec-04-a2
```

API endpoint:
```bash
curl "$JETTY_HOST/v1/fleet/$RUN_ID/status" | jq
```

Returns structured data: per-agent token usage, completion percentage, file
modifications in progress, error counts, estimated time remaining.

**What it eliminates**:
- Black-box debugging during long runs
- Manual Jetty web UI checks
- Guessing which agent is stuck and why
- Post-hoc cost analysis (tokens are tracked live)

---

### 11. Cross-Agent Memory

**Pain point**: Agents build up knowledge during a run (type renames, removed
modules, deprecated patterns) that is lost when their sandbox dies. The next
run's agents rediscover the same things from scratch.

**Current workaround**: `.fleet-state.json` tracks which files were processed,
but not what was learned. The dependency graph caches file-to-chapter mappings,
but not semantic knowledge.

**Proposal**: A persistent memory layer scoped to the fleet type (across runs).

```bash
# Agent discovers a codebase-wide rename
jetty-memory write --scope=fleet --key="renames/ShardSpec" \
  '{"old": "ShardSpec", "new": "ShardDescriptor", "since_sha": "abc123"}'

# Next run's agents read accumulated knowledge
jetty-memory read --scope=fleet --prefix="renames/"
# Returns: [{"key": "renames/ShardSpec", "value": {...}, "written_by": "sec-05-a1", "run": "guide-sync-2026-04-04"}]

# Agent learns a cross-reference convention
jetty-memory write --scope=fleet --key="conventions/chapter-links" \
  '{"pattern": "use relative paths, not absolute", "example": "../04-boundary-2/01-coordination.md"}'
```

Over multiple runs the fleet accumulates institutional knowledge: common
renames, deprecated patterns, cross-reference conventions, known false
positives. New agents start with this context instead of rediscovering it.

Memory entries include provenance (which agent wrote them, which run) and can
be expired or overwritten as the codebase evolves.

**What it eliminates**:
- Redundant discovery across runs
- Agents making the same mistakes the fleet already learned from
- Manual runbook updates to encode learned patterns

---

## Priority Matrix

| Feature | Effort | Impact | What It Eliminates |
|---------|--------|--------|--------------------|
| Shared artifact store | M | High | GitHub as data bus, branch push/fetch |
| Webhook completion | S | High | Polling loop (thousands of API calls) |
| Agent chaining / DAG | M | High | Multi-phase orchestration |
| Fleet shared state | S | Medium | Custom state management code |
| Shared repo snapshot | M | High | N redundant clones (saves N x 30s) |
| Agent-to-agent messaging | L | High | Agentic drift (top failure mode) |
| Built-in merge service | M | High | merge.rs, worktree management |
| Fleet templates | L | Very High | The orchestrator binary entirely |
| Speculative execution | L | Medium | Sequential phase latency |
| Live observatory | M | Medium | Black-box debugging |
| Cross-agent memory | M | Medium | Repeated discovery across runs |

**Highest bang-for-buck**: Shared artifact store + webhook + agent chaining.
Those three together eliminate merge.rs, the polling loop, and Phase 2b
coordinator launch — roughly 40% of the orchestrator code.

**Longest lever**: Fleet templates. If Jetty becomes the orchestrator, the
local binary reduces to `jetty fleet run guide-sync --tier=3 --full` and the
entire `crates/fleet-orchestrator/` crate becomes unnecessary.
