# Deeper Research: Fleet-Native Primitives for Jetty Platform

> 21 agents across 6 phases. Re-synthesized against the 11 feature proposals
> in `jetty-feature-proposals.md`, targeting **Mise/Jetty platform changes**
> (not the Rust orchestrator CLI).

## Context

The fleet-orchestrator (`crates/fleet-orchestrator/`, 5,041 LOC Rust) orchestrates
20-100 agents on Jetty. It works, but 60% of its code handles concerns the
platform could own. The 11 feature proposals describe platform primitives that
would let Jetty become the orchestrator, shrinking or eliminating the local binary.

This research provides evidence-backed guidance for building those 11 features
into Jetty's three services (Mise, MLCBakery, Spot).

### What Jetty Already Has

| Capability | Status | Where |
|-----------|--------|-------|
| Webhooks on completion | **EXISTS** | `POST webhook_url` with HMAC-SHA256 signing |
| DAG workflow engine | **EXISTS** | 33+ step types, path-expression dependencies |
| Fan-out/fan-in | **EXISTS** | `list_emit_await` → `extract_from_trajectories` |
| Agent sandboxes | **EXISTS** | claude-code, codex, gemini-cli in Daytona |
| Snapshot selection | **EXISTS** | `snapshot: python312-uv` in agent config |
| `Step.depends_on` field | **EXISTS but ignored** | `mise/flows/types.py:67` |
| MCP server injection | **EXISTS** | `mise/flows/steps/runbook.py:1084-1134` |
| Temporal signals | **EXISTS** | Used for log streaming (`flow_workflows.py:88-106`) |
| SSE event streaming | **EXISTS** | `mise/api/endpoints/flows.py:1560` |
| Per-collection metering | **EXISTS** | `stepsUsed / stepLimit` |
| Langfuse tracing | **EXISTS** | Per-step traces with token counts |

### What Jetty Does NOT Have

- `fleet_id` concept grouping multiple trajectories
- Inter-agent communication channel
- Shared filesystem or artifact store between sandboxes
- DAG scheduler using the existing `depends_on` field
- Fleet-level resource management or cost budgets
- Repository snapshot caching (each agent clones independently)
- Cross-agent memory across runs

---

## The 11 Proposals: Evidence-Backed Design Guidance

### Proposal 1: Shared Artifact Store

**Replaces**: GitHub as the data bus between agents (branch push/fetch).

**Research evidence**:
- P3.4.F4: Daytona Volumes are FUSE-based S3 mounts. Multiple sandboxes can
  mount the same volume simultaneously. Up to 100 volumes per org, free.
- P3.4.F2: Daytona Snapshots (OCI images) can bake artifacts into the sandbox image.
- P1.2.F6: Dagger's cache volumes persist across ephemeral runners — validates
  the pattern of external volumes surviving sandbox lifecycle.
- P3.3.F5: CALM theorem — if agents write to disjoint paths, artifact merging
  is monotonic (commutative, associative, idempotent). No coordination needed.

**Design recommendation**: Fleet-scoped Daytona Volume mounted at
`/fleet/{run_id}/artifacts/`. Each agent writes to its own prefix
(`/fleet/{run_id}/artifacts/{agent_id}/`). Coordinators and the merge step
read all prefixes. Volume lifecycle tied to fleet run.

```
Agent A  --write-->  /fleet/{run_id}/artifacts/sec-04-a1/
Agent B  --write-->  /fleet/{run_id}/artifacts/sec-04-a2/
Coord    --read-->   /fleet/{run_id}/artifacts/sec-04-*/
```

**Key constraint**: Daytona Volumes are "generally slower for read and write
operations compared to local sandbox filesystem" (FUSE overhead). Write-heavy
agent work should remain on local disk; artifacts are written to the volume
only as final output.

**Extension point in Mise**: `StorageProtocol` (`mise/storage/protocol.py`) is
pluggable. A fleet-scoped storage backend wrapping Daytona Volumes would
implement this interface. The `JettyExtension` model gains
`fleet.shared_storage_prefix`.

**Confidence**: MEDIUM-HIGH. Daytona Volumes are documented and production-ready.
Unknown: whether Mise's `RunbookStep` can pass volume mount parameters through
to Daytona sandbox creation.

---

### Proposal 2: Webhook / Callback on Completion

**Status**: **ALREADY EXISTS** in Jetty.

**What's available**: `webhook_url` and `webhook_secret` parameters on async
workflow submission. Fires on completion/failure with HMAC-SHA256 signed payload
containing trajectory ID, status, step outputs, and metadata.

**Research evidence**:
- P1.7.F1: Polling overhead is detection latency (0-60s per cycle), not HTTP
  cost. Webhooks eliminate this entirely.
- P3.1.F1: Temporal's Sliding Window pattern uses signals for child-to-parent
  completion notification — webhooks serve the same role for the external
  orchestrator.

**What's still needed for fleets**: The webhook fires per-trajectory, not
per-fleet. The orchestrator needs to aggregate N webhook callbacks into
fleet-level progress. Two approaches:

1. **Orchestrator hosts a webhook endpoint** — receives callbacks, updates
   internal state, triggers next phase when quorum is met. The fleet-orchestrator
   Rust binary would add an `axum` HTTP server for this.

2. **Jetty adds fleet-level webhook** — fires when all agents in a fleet reach
   terminal state or when a configurable threshold is met
   (`ToleratedFailurePercentage` pattern from AWS Step Functions [P1.2.F3]).

**Recommendation**: Use existing per-trajectory webhooks now. Propose fleet-level
webhook aggregation as a Jetty enhancement (lower priority since the per-agent
webhooks are already the hard part).

**Confidence**: HIGH. Feature exists. Integration is engineering, not research.

---

### Proposal 3: Agent Chaining / DAG Workflows

**Replaces**: The orchestrator's multi-phase state machine (launch agents, poll,
launch coordinators, poll again).

**Research evidence**:
- P3.1.F1: Temporal's Sliding Window Batch is the canonical pattern. Parent
  workflow starts children with `ParentClosePolicy.ABANDON`, children signal
  parent via workflow ID (persists across Continue-As-New).
- P3.1.F5: Temporal task queue priority (1-5 levels, GA) provides native
  critical-path-first dispatch.
- P3.1.F2: 100 child workflows generate ~800 Temporal history events — well
  within the 51,200 limit.
- P3.1.F6: DAG dispatch is naturally deterministic (compatible with Temporal
  replay). Ready-queue = `{n : in_degree[n] == 0}`.
- P1.2.F5: Buck2 DICE eliminated phase barriers for 2x speedup by using a
  single incremental dependency graph.
- P1.5.F10: GitLab CI's `needs` keyword: jobs start when actual deps complete,
  not when entire stage finishes.

**What already exists in Mise**:
- `Step.depends_on` at `mise/flows/types.py:67` — the field is defined but the
  workflow engine ignores it.
- `list_emit_await` step — launches parallel child workflows and collects results.
- `FlowWorkflow.run` at `mise/flows/flow_workflows.py:148` — the sequential
  step loop (`for step_name in inputs.steps`).

**Design recommendation**: Wire `depends_on` into `FlowWorkflow.run`. Replace
the sequential loop with a ready-queue dispatch loop:

```python
# In flow_workflows.py, replace:
#   for step_name in inputs.steps:
#       await execute_step(step_name)
#
# With:
in_degree = compute_in_degree(steps)
completed = set()
while len(completed) < len(steps):
    ready = [s for s in steps if in_degree[s] == 0 and s not in completed]
    results = await asyncio.gather(*[execute_step(s) for s in ready])
    for s in ready:
        completed.add(s)
        for successor in dependents[s]:
            in_degree[successor] -= 1
```

For fleet chaining (Proposal 3's `depends_on` at launch time), extend
`JettyExtension` with fleet dependency fields and use Temporal signals:

```json
{
  "jetty": {
    "fleet": {
      "agent_id": "coord-04",
      "depends_on": ["sec-04-a1", "sec-04-a2"],
      "trigger": "all_completed"
    }
  }
}
```

Mise holds the coordinator workflow in a `workflow.wait_condition()` until
signals from its dependencies arrive.

**Trigger modes** (from the proposal):
- `all_completed` — Temporal `wait_condition(lambda: all deps signaled success)`
- `any_completed` — `wait_condition(lambda: any dep signaled)`
- `all_terminal` — `wait_condition(lambda: all deps signaled any terminal state)`
- `speculative` (Proposal 9) — `wait_condition(lambda: completed_count / total >= threshold)`

**Confidence**: HIGH. The Temporal primitives (child workflows, signals,
wait conditions) exist and are production-proven [P3.1.F1-F6]. The main work is
wiring `depends_on` in the Python workflow engine (~100 lines of topological
sort + ready-queue dispatch).

---

### Proposal 4: Fleet-Scoped Shared State

**Replaces**: Custom in-memory status tracking in the orchestrator.

**Research evidence**:
- P3.5.F8: Temporal Search Attributes are indexed KV pairs on workflow
  executions. Custom attributes like `fleet_id`, `agent_role`, `section_id`
  enable fleet-level queries: `temporal workflow list -q "fleet_id = 'X'"`.
- P1.2.F10: NATS JetStream KV store — sub-millisecond, built-in. But adds
  operational overhead vs Temporal's native support.
- P1.7.F7: At <1000 messages per fleet run, Temporal signals are sufficient.
  No external message bus needed.

**Design recommendation**: Two layers:

1. **Temporal Search Attributes** (fleet metadata): Add `fleet_id` (Keyword),
   `agent_role` (Keyword), `section_id` (Keyword), `cost_usd` (Double) to
   `FlowWorkflowInput`. Set on workflow start. Enables fleet-level queries
   through Temporal's existing List API.

2. **Fleet state KV API** (agent-writable): New Mise endpoint backed by
   PostgreSQL (or Redis for lower latency):
   ```
   PUT  /v1/fleet/{run_id}/state/{key}
   GET  /v1/fleet/{run_id}/state?prefix={prefix}
   ```
   Injected into agent sandboxes as `FLEET_STATE_URL` environment variable.
   Agents write progress; coordinators read it.

**Extension point**: `JettyExtension.fleet` gains `fleet_id` and `run_id`.
Sandbox env setup (`runbook.py`) injects `FLEET_ID`, `FLEET_STATE_URL`.
MCP server injection could provide a `fleet_state` tool instead of raw HTTP.

**Confidence**: MEDIUM-HIGH. Temporal Search Attributes are production-ready.
The KV API is a standard CRUD endpoint with fleet-scoped access control.

---

### Proposal 5: Shared Repository Snapshot

**Replaces**: N redundant clones (N x 5-30s, N x 200MB bandwidth).

**Research evidence**:
- P3.4.F1: Daytona warm pool provides millisecond launches from pre-instantiated
  sandboxes using default snapshots.
- P3.4.F2: Daytona Snapshots are OCI images built from Dockerfiles. Can include
  `RUN git clone`. Primary creation mechanism since SDK v0.21.0.
- P3.4.F3: Sub-90ms warm start (image cached), multi-second cold start.
  Benchmarked: 71ms creation + 67ms execution + 59ms cleanup = 197ms round-trip.
- P3.4.F4: Daytona Volumes can mount the same repo into N sandboxes simultaneously.
- P3.4.F5: Rate limits: 300-600 creations/min. Tier 2 supports 100 vCPU pool.
- P3.4.F7: 37,000 sandboxes/week validated at Laude Institute.

**What already exists**: The agent config accepts `snapshot: python312-uv`.
Custom snapshots may already work if Jetty passes this through to Daytona.

**Design recommendation**: Two approaches (not mutually exclusive):

1. **Custom snapshot with pre-cloned repos** (Dockerfile-based):
   ```dockerfile
   FROM daytona-default
   RUN git clone --depth=1 https://github.com/ahrav/gossip-rs /workspace/source
   RUN git clone --depth=1 https://github.com/ahrav/gossip-rs-learning-guide /workspace/guide
   ```
   Rebuild via CI when Cargo.lock or relevant paths change. Agent config:
   `snapshot: guide-sync-v2`.

2. **Shared read-only Volume** for the source repo:
   ```json
   {
     "jetty": {
       "fleet": {
         "volumes": [{
           "name": "source-repo",
           "mount": "/workspace/source",
           "mode": "read_only"
         }]
       }
     }
   }
   ```
   The orchestrator creates one volume with the source repo, mounts it into
   all agent sandboxes.

**Quantified improvement**: 4-37 minutes saved per fleet run (depending on
agent count and clone time). For 100 agents at 15s average clone time: 25
minutes of aggregate clone time eliminated.

**Key unknown**: Whether Mise's `RunbookStep.__call__` passes custom snapshot
names and volume mounts through to the Daytona API. This is the #1 thing to
validate with the Jetty team.

**Confidence**: MEDIUM. Daytona capabilities are documented. Unknown: Jetty's
abstraction layer.

---

### Proposal 6: Agent-to-Agent Messaging

**Replaces**: Agents operating in total isolation. Eliminates redundant
discovery and agentic drift.

**Research evidence**:
- P1.2.F2: Temporal signals as agent-to-workflow-actor mailbox. Each signal is
  durably recorded, providing audit trail.
- P1.1.F7: Vector clocks for causal ordering. For 20-100 agents, O(100)
  integers per message — feasible.
- P1.7.F7: Latency comparison — NATS 50-200μs, Redis 200-500μs, Temporal
  1-10ms. All overkill for <1000 msgs/run.
- P1.5.F11: Anthropic's multi-agent system uses filesystem as coordination bus.
  Pragmatic and battle-tested for co-located agents.

**Design recommendation**: MCP tool server injected into agent sandboxes.
Agents call `fleet_message` tool to publish/subscribe:

```
# MCP tool: fleet_message_publish
{"topic": "sec-04", "type": "rename", "data": {"old": "ShardSpec", "new": "ShardDescriptor"}}

# MCP tool: fleet_message_poll
{"topic": "sec-04", "filter": "type=rename"}
```

Backend options (pick one):
1. **Temporal signals** — zero infrastructure, durable, auditable. Messages
   route through the fleet parent workflow as signal relay. Latency: 1-10ms.
2. **Fleet state KV** (Proposal 4) — messages stored as time-ordered keys in
   the fleet state store. Agents poll on tool call.
3. **NATS JetStream** — lowest latency, highest operational cost. Only justified
   if message rates exceed 10K/run.

**Recommendation**: Start with Temporal signal relay (option 1). The fleet
parent workflow receives `fleet_message` signals and relays to subscribed child
workflows. This uses existing infrastructure and provides durability + audit.

**Confidence**: MEDIUM. The Temporal signal mechanism is proven [P3.1.F1]. The
MCP injection point exists [runbook.py:1084-1134]. Unknown: whether agent
runtimes (claude-code, codex, gemini-cli) will actually call the MCP tool
proactively during execution.

---

### Proposal 7: Built-in Merge Service

**Replaces**: `merge.rs` (~200 lines of git worktree management).

**Research evidence**:
- P3.3.F5: CALM theorem — disjoint write sets form a join-semilattice. Merge
  is commutative, associative, idempotent. Order does not matter.
- P3.3.F4: Spark DAGScheduler — independent materialization. Keep succeeded
  task outputs, re-run only failed tasks.
- P3.3.F1: AWS Step Functions — status-segregated result files
  (SUCCEEDED/FAILED). Never combined across success/failure boundaries.
- P3.3.F3: Mergify — n-ary bisection for batch failure isolation. O(log n)
  to find the failing unit.
- P3.3.F8: Bors-ng — bisection state machine. Sub-batches merge independently
  while bisection continues on failing sub-batches.
- P3.3.F2: Zuul CI — cascade invalidation. If dependency fails, all downstream
  speculatively-tested changes are retested.

**Design recommendation**: Merge endpoint in Mise:

```
POST /v1/fleet/{run_id}/merge
{
  "sources": ["sec-04-a1", "sec-04-a2", "sec-04-a3"],
  "target_repo": "ahrav/gossip-rs-learning-guide",
  "target_branch": "guide-sync/section-04/{run_id}",
  "strategy": "sequential",
  "on_conflict": "bisect_and_report"
}
```

Three conflict strategies backed by research:
- `skip_and_report` (current behavior) — simple, loses data silently [P3.3.F6]
- `bisect_and_report` (Mergify/Bors-ng pattern) — isolate conflicting branch
  via binary search, merge the non-conflicting subset [P3.3.F3, P3.3.F8]
- `cascade_invalidate` (Zuul pattern) — mark all downstream of a conflict as
  stale [P3.3.F2]

**Partial-success semantics** (the hard part):
- Monotonic case (disjoint writes): always safe to merge subset of succeeded
  agents. Missing agents = no change to those files [P3.3.F5].
- Non-monotonic case (cross-references): post-merge validation required. Scan
  for broken links/refs pointing to chapters owned by failed agents. Mark those
  referring chapters as stale too (cascade invalidation) [P3.3.F2].

**Confidence**: MEDIUM. The merge algorithms are well-understood. Implementation
requires Mise to have git credentials and worktree capability server-side.

---

### Proposal 8: Fleet Templates

**Replaces**: The entire orchestrator binary.

**Research evidence**:
- P1.5.F10: GitLab CI DAG — `needs` keyword replaced stage barriers. Jobs
  start when actual deps complete.
- P1.2.F8: Airflow dynamic task mapping — `expand()` separates task count from
  concurrency limit. Runtime-determined parallelism.
- P1.2.F5: Buck2 DICE — single incremental dependency graph.
- P1.5.F1: Google Rosie — shard-test-mail-submit. Independent pipelines per
  shard. Ownership-based partitioning.

**What already exists in Jetty**: The workflow definition system with 33+ step
types, `list_emit_await` for fan-out, `extract_from_trajectories` for fan-in,
and data wiring via path expressions.

**Design recommendation**: Fleet templates compose existing primitives:

```yaml
fleet: guide-sync
stages:
  - name: chapter-agents
    step: list_emit_await
    config:
      items_path: init_params.manifests  # computed by partitioner
      task_reference:
        task_name: guide-sync-chapter
      data_mapping:
        write_set: "{{ $item.write_set }}"
        section: "{{ $item.section }}"
      execution_config:
        max_parallel: 15
        timeout_seconds: 5400

  - name: coordinators
    step: list_emit_await
    depends_on: chapter-agents           # Proposal 3
    trigger: all_terminal
    config:
      items_path: init_params.sections
      task_reference:
        task_name: guide-sync-coordinator
      execution_config:
        max_parallel: 8

  - name: merge
    step: fleet_merge                    # Proposal 7
    depends_on: [chapter-agents, coordinators]
    config:
      strategy: bisect_and_report

  - name: create-prs
    step: fleet_create_prs
    depends_on: merge
```

This is an evolutionary step: compose existing Jetty primitives (once Proposals
3 and 7 are built) into a declarative fleet topology. The partitioning logic
(currently `partitioner.rs`) becomes a pre-processing step that generates
`init_params.manifests`.

**Confidence**: LOW-MEDIUM. Depends on Proposals 3 and 7 being built first.
The template format is speculative.

---

### Proposal 9: Speculative Execution

**Replaces**: Sequential phase boundaries (coordinators wait for ALL chapter
agents).

**Research evidence**:
- P3.2.F1: Wang-Joshi-Wornell (ACM TOMPECS 2019) — for heavy-tailed execution
  times, replicating the slowest 5-10% reduces BOTH latency AND cost.
- P3.2.F2: Dolly (NSDI 2013) — 5% resource budget yields 34-46% speedup.
  Budget "saturates" at 5%.
- P3.2.F3: Mantri (OSDI 2010) — cause-aware restarts succeed 70% vs 15% for
  blind duplication. Classify: resource contention (restart), data skew (don't
  restart), machine failure (restart on different machine).
- P3.2.F6: Heuristic detection at $0 outperforms LLM judges. 100% precision
  on loop detection. Tiered: hash comparison → state delta → embedding → LLM.

**Design recommendation**: The `speculative` trigger mode from Proposal 3:

```json
{
  "depends_on": ["sec-04-a1", "sec-04-a2", "sec-04-a3"],
  "trigger": "speculative",
  "speculative_threshold": 0.8
}
```

Coordinator starts when 80% of dependencies complete. On remaining completions,
the coordinator receives incremental updates via fleet messaging (Proposal 6).
On dependency failure, coordinator discards speculative work for that section.

**Straggler mitigation** (separate from speculative coordinators):
- Elapsed-time-ratio heuristic: flag agents exceeding 2x median [P3.2.F6]
- Cost-bounded re-dispatch: 5% speculative budget [P3.2.F2]
- Cause classification: loop detection (kill+restart) vs large workload (wait)
  [P3.2.F3]

**Break-even**: Speculation is net-positive when P(transient cause) > 0.33.
Mantri data says 70% of restarts succeed → strongly net-positive [P3.2.F3].

**Confidence**: MEDIUM. The speculative trigger is straightforward to implement
in the DAG scheduler (Proposal 3). Straggler detection requires progress
signals from agents, which Jetty doesn't currently expose.

---

### Proposal 10: Live Agent Observatory

**Replaces**: Black-box debugging during 90-minute fleet runs.

**Research evidence**:
- P3.5.F1: OpenTelemetry GenAI Semantic Conventions — standard schema with
  `gen_ai.agent.id`, `gen_ai.client.token.usage`, agent spans for teams/tasks.
  Adopted by Datadog, Grafana.
- P3.5.F2: LiteLLM hierarchical budgets — per-key, per-team, per-agent cost
  tracking with Prometheus metrics. Already in Mise's dependency tree.
- P3.5.F3: Agent Contracts (AAMAS 2026) — conservation law: sum of child
  budgets must not exceed parent's remaining budget. Prevents the documented
  7x cost overrun [P1.3.F5].
- P3.5.F4: Mise already has Langfuse (per-step traces + token counts), GCP
  Cloud Monitoring (custom metrics), and Stripe metering (steps used/limit).
  None are fleet-aware.
- P3.5.F5: Agent drift detection — scope violations, diff size ratio,
  terminology consistency. Computable from merge artifacts post-execution.
- P3.5.F7: Microsoft Agent Governance Toolkit (April 2026) — SRE model for
  agents: SLOs, error budgets, burn-rate tracking, circuit breakers.
- P3.5.F8: Temporal Search Attributes — lowest-effort fleet dashboard.
  `temporal workflow list -q "fleet_id = 'X' AND status = 'Running'"`.

**Design recommendation**: Three-layer observatory:

**Layer 1 — Per-agent metrics** (extend `_base_usage()` in `usage_tracking.py`):
```python
FleetAgentMetrics = {
    "fleet_id": str,
    "agent_id": str,
    "section_id": str,
    "agent_role": str,          # chapter_agent | coordinator
    "input_tokens": int,
    "output_tokens": int,
    "cost_usd": float,
    "duration_seconds": float,
    "status": str,
    "files_modified": int,
    "scope_violations": int,    # drift detection
}
```

**Layer 2 — Storage** (three channels, no new infrastructure):
1. Temporal Search Attributes: `fleet_id`, `agent_role`, `cost_usd` on each
   workflow execution. Enables fleet queries via existing Temporal API.
2. Langfuse: Add `fleet_id` to trace metadata. Groups traces by fleet run.
3. PostgreSQL `trajectories` table: Add `fleet_id` column for historical queries.

**Layer 3 — Dashboard** (extend Spot):
Real-time fleet view at `flows.jetty.io/{collection}/{task}/fleet/{run_id}`.
Built from Temporal List API + Langfuse aggregation. SSE streaming
(`flows.py:1560`) extended with fleet events.

**Budget enforcement**: Conservation law [P3.5.F3]. Fleet has total budget;
each section receives sub-budget; each agent receives sub-sub-budget. Check
cumulative spend between wave launches. At 80% → reduce concurrency. At 95% →
halt new launches.

**Confidence**: MEDIUM-HIGH. Individual components (Langfuse, Temporal search
attributes, SSE) are production-ready. Integration is engineering.

---

### Proposal 11: Cross-Agent Memory

**Replaces**: Agents rediscovering the same things every run.

**Research evidence**:
- P1.1.F8: Merkle-CRDTs — content-addressed DAGs with CRDT payloads converge
  to unique global state without consensus. Git's object model is already a
  Merkle-DAG.
- P3.3.F5: CALM theorem — monotonic additions to a knowledge store are
  coordination-free. Memory entries that only add (never revoke) are safe for
  concurrent access.
- P1.5.F8: OpenHands event-sourced state — chronological event stream with
  deterministic replay. Accumulated knowledge as append-only log.

**Design recommendation**: Fleet memory as a persistent KV store scoped to
fleet type (not run):

```
PUT  /v1/fleet-memory/{fleet_type}/{key}
GET  /v1/fleet-memory/{fleet_type}?prefix={prefix}
```

Backed by MLCBakery's existing provenance model (`EntityRelationship`):
- Memory entries are entities with `written_by` (agent ID), `run_id`, `sha`
  (code version when written).
- Entries expire when their `sha` no longer exists in the repo (stale knowledge).
- New agents read accumulated knowledge at run start; knowledge is injected
  into the runbook template or as a fleet-scoped file.

**Confidence**: LOW-MEDIUM. The concept is validated by OpenHands and Anthropic's
multi-agent system. No production fleet-memory system exists to study.

---

## Priority Matrix (Research-Adjusted)

| # | Proposal | Effort | Impact | Depends On | Research Confidence |
|---|----------|--------|--------|-----------|-------------------|
| 2 | **Webhook completion** | — | — | **Already exists** | — |
| 3 | **Agent chaining / DAG** | M | High | Wire `depends_on` | HIGH (P3.1.F1-F6) |
| 1 | **Shared artifact store** | M | High | Daytona Volumes | MEDIUM-HIGH (P3.4.F4) |
| 5 | **Shared repo snapshot** | S | High | Custom snapshots | MEDIUM (P3.4.F1-F3) |
| 4 | **Fleet shared state** | S | Medium | Temporal Search Attrs | MEDIUM-HIGH (P3.5.F8) |
| 10 | **Live observatory** | M | Medium | Fleet shared state | MEDIUM-HIGH (P3.5.F1-F8) |
| 7 | **Built-in merge** | M | High | Artifact store | MEDIUM (P3.3.F1-F8) |
| 6 | **Agent messaging** | L | High | MCP + Temporal signals | MEDIUM (P1.2.F2) |
| 9 | **Speculative execution** | L | Medium | Agent chaining | MEDIUM (P3.2.F1-F3) |
| 8 | **Fleet templates** | L | Very High | Chaining + merge | LOW-MEDIUM |
| 11 | **Cross-agent memory** | M | Medium | Fleet shared state | LOW-MEDIUM |

### Recommended Build Order

```
Phase A (foundations):
  Proposal 3 (Agent Chaining)  ─── wire depends_on, ~100 lines Python
  Proposal 5 (Repo Snapshots)  ─── validate snapshot passthrough, custom Dockerfile
  Proposal 4 (Fleet State)     ─── fleet_id on trajectories, Temporal search attrs

Phase B (data plane):
  Proposal 1 (Artifact Store)  ─── Daytona Volume per fleet run
  Proposal 10 (Observatory)    ─── fleet dashboard in Spot, budget enforcement

Phase C (coordination):
  Proposal 7 (Merge Service)   ─── server-side merge with bisection
  Proposal 6 (Messaging)       ─── MCP tool + Temporal signal relay

Phase D (advanced):
  Proposal 9 (Speculative)     ─── speculative trigger mode
  Proposal 8 (Fleet Templates) ─── declarative fleet topology
  Proposal 11 (Cross-Agent Memory) ─── persistent fleet knowledge
```

**Highest bang-for-buck**: Proposals 3 + 5 + 4. Agent chaining eliminates the
orchestrator's phase management. Repo snapshots eliminate clone overhead.
Fleet state enables fleet-level queries. Together they eliminate ~40% of the
orchestrator code.

**Longest lever**: Proposal 8 (Fleet Templates). If Jetty becomes the
orchestrator, the entire `crates/fleet-orchestrator/` crate becomes unnecessary.
But it depends on Proposals 3 and 7 being built first.

---

## Key Research Findings That Survived Adversarial Review

| Finding | Status | Implication for Jetty |
|---------|--------|----------------------|
| CALM theorem: disjoint writes are monotonic | CONFIRMED | Artifact store + merge service can safely compose partial results |
| Temporal sliding window signal pattern | CONFIRMED | Agent chaining implementation design is proven |
| Daytona warm pool sub-90ms | CONFIRMED | Repo snapshots provide major speedup |
| OTel GenAI semantic conventions | CONFIRMED | Observatory should use standard schema |
| Mantri cause-aware straggler detection 70% | CONFIRMED | Speculative execution is cost-effective |
| Agent Contracts conservation law | CONFIRMED | Budget enforcement prevents cost runaway by construction |
| 5% speculative budget → 34-46% speedup | CONFIRMED | Cost-bounded speculation is net-positive |
| Mergify n-ary bisection for conflict isolation | CONFIRMED | Merge service should bisect, not skip |

## Key Claims That Were Refuted

| Claim | Verdict | Corrected Understanding |
|-------|---------|------------------------|
| n^1.7 agent drift scaling | REFUTED — no such formula in cited paper | Agent drift is real but not quantified by a power law |
| Temporal signals <10ms | REFUTED — no documentation supports this | Signals are fast but exact latency undocumented |
| 14x parallel merge speedup | UNVERIFIABLE — fabricated arithmetic | Parallel section merges help (3-8 sections) but not 14x |
| MapReduce backup tasks 44% improvement | INVERTED — actually ~31% | Backup tasks work but the magnitude was overstated |
| SagaLLM published at VLDB 2025 | WRONG VENUE — arXiv preprint | The technique is valid; the venue attribution was inflated |

---

## References

1. Cemri et al., "Why Do Multi-Agent LLM Systems Fail?" (arXiv:2503.13657)
2. Wang, Joshi, Wornell, "Efficient Straggler Replication" (ACM TOMPECS 2019)
3. Ananthanarayanan et al., "Mantri: Reining in Outliers" (OSDI 2010)
4. Ananthanarayanan et al., "Dolly: Attack of the Clones" (NSDI 2013)
5. CALM theorem — Hellerstein & Alvaro (2019)
6. Temporal Sliding Window Batch (github.com/temporalio/samples-java)
7. Temporal Task Queue Priority (docs.temporal.io)
8. OpenTelemetry GenAI Semantic Conventions (opentelemetry.io)
9. Ye & Tan, "Agent Contracts" (arXiv:2601.08815, AAMAS 2026)
10. Daytona Snapshots, Volumes, Warm Pool (daytona.io/docs)
11. Zuul CI Gating (zuul-ci.org)
12. Mergify Speculative Checks (docs.mergify.com)
13. Bors-ng Batcher (github.com/bors-ng/bors-ng)
14. Spark DAGScheduler (github.com/apache/spark)
15. LiteLLM Budget/Cost Tracking (docs.litellm.ai)
16. Microsoft Agent Governance Toolkit (github.com/microsoft/agent-governance-toolkit)
17. Jetty Webhooks (docs.jetty.io/docs/api/webhooks)
18. Jetty Workflow Orchestration (docs.jetty.io/docs/core-concepts/workflow-orchestration)
19. Google SWE Book Ch. 22: Large-Scale Changes (abseil.io)
20. Shopify Merge Queue (shopify.engineering)
21. GitLab CI DAG (about.gitlab.com)
22. Buck2 DICE (engineering.fb.com)
23. Addy Osmani, "Code Agent Orchestra" (addyosmani.com)
24. DORA 2025 (dora.dev)
25. Dean & Ghemawat, "MapReduce" (OSDI 2004)
