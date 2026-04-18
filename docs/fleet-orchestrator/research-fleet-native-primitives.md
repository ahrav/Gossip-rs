# Research Topic: Fleet-Native Primitives for Agent Orchestration Platforms

An open-ended research agenda for extending agent execution platforms (Jetty/Mise)
with first-class support for coordinated multi-agent fleets. Grounded in
real-world experience orchestrating 20-100 parallel agents and a thorough
analysis of the Jetty platform architecture (Mise, MLCBakery, Spot).

---

## How to Use This Document

This document is designed to be **self-contained context** for an agent or team
exploring any of the five research tracks. It includes:

1. **The experiment** — A working fleet orchestrator we built, with source code
   paths and architecture diagrams, showing exactly what works, what breaks,
   and what had to be built externally
2. **The platform** — Full architecture of Jetty's three services (Mise,
   MLCBakery, Spot) with file paths and line numbers into the source code
3. **The research tracks** — Five independent areas of investigation, each
   with design questions, prior art, and evaluation criteria
4. **The references** — Links to all source code, documentation, and academic
   literature

### Repository Locations

| Repo | Local Path | Purpose |
|------|-----------|---------|
| **gossip-rs** | `/Users/ahrav/Projects/gossip-rs` | Fleet orchestrator experiment |
| **mise** | `/Users/ahrav/Projects/mise` | Jetty execution engine (API + Temporal + Daytona) |
| **mlcbakery** | `/Users/ahrav/Projects/mlcbakery` | Jetty metadata/provenance service |
| **spot** | `/Users/ahrav/Projects/spot` | Jetty web frontend (Next.js) |
| **gossip-rs-learning-guide** | `/Users/ahrav/Projects/gossip-rs-learning-guide` | The 99-chapter guide being synced |

### Quick Start for Researchers

To explore a specific track:
1. Read the experiment section to understand the pain points
2. Read the platform architecture section to understand constraints
3. Read the research track's design questions
4. Browse the source code at the paths listed in the references
5. Start with the "Prior Art to Investigate" list for external evidence

---

## Motivation

AI agent platforms today execute agents in isolation — one sandbox, one task,
one result. But real-world workloads increasingly involve **fleets**: 10-100
agents working on related subtasks that must be coordinated, merged, and
validated as a unit. Current platforms force fleet operators to build external
orchestrators that handle partitioning, inter-agent coordination, merge
strategies, and state tracking — all over REST APIs never designed for this
purpose.

### Evidence From Practice

We built a fleet orchestrator that synchronizes a 99-chapter learning guide
with a Rust codebase using 20-100 parallel agents on Jetty. The experience
revealed that:

- **60% of orchestrator code** handles concerns the platform could own: polling
  for completion, merging branches, managing state, coordinating phases
- **GitHub becomes the data bus** between agents (branch push/fetch), adding
  latency and rate-limit pressure for what should be internal data transfer
- **Agents are blind to siblings** — when one agent discovers a type rename,
  others independently rediscover it or produce inconsistent fixes
- **Sequential phase boundaries** waste wall-clock time — coordinators idle
  while the last chapter agent runs
- **Every fleet operator rebuilds** the same fan-out/poll/fan-in/merge pattern

### The Research Question

**What platform-level primitives would transform agent orchestration from
external bolted-on coordination to a first-class capability of the execution
platform itself?**

This question spans five areas of distributed systems design, each explored
below as an independent research track.

---

## The Experiment: Guide-Sync Fleet Orchestrator

A Rust binary (`crates/fleet-orchestrator/`, 5,041 LOC, 102 tests) that
orchestrates 20-100 Jetty agents to synchronize a 99-chapter learning guide
with a Rust codebase. This is the real-world experiment that generated the
pain points driving this research.

### What It Does

```
Local Machine                 Jetty Cloud                    GitHub
(Rust orchestrator)           (Daytona sandboxes)            (repos + PRs)

Phase 0: Build dependency     
  graph, detect changed       
  source files, propagate     
  to affected chapters        

Phase 1: Partition chapters   Chapter agents (20):
  into disjoint write sets    - Clone source repo (read)  -> gossip-rs
  Launch agents in waves      - Clone guide repo (write)  -> learning-guide
  of 15 via Jetty API         - Audit chapters vs source
                              - Fix drift
                              - Push branch               -> guide-sync/{id}

Phase 2a: Poll agents         
  (adaptive 60s->30s)         Coordinator agents (8):
Phase 2b: Launch              - Fetch chapter branches     <- guide-sync/{id}
  coordinators (Tier 3)       - Merge within section
                              - Cross-reference validation
                              - Push integration branch    -> section-{id}

Phase 3: Merge + PR
  Create git worktree
  Fetch section branches                                   <- section-{id}
  Create section-level PRs                                 -> PRs (up to 14)
  GraphQL batch cleanup                                    -> delete branches

Phase 4: State update
  flock + atomic write
  Success-only updates
```

### Source Code Map

All code lives in the gossip-rs repository.

**Orchestrator crate** (`crates/fleet-orchestrator/`):

| File | Lines | Purpose |
|------|-------|---------|
| `src/main.rs` | 880 | 5-phase pipeline: graph → partition → launch → poll → merge → state |
| `src/graph.rs` | 476 | Bipartite dependency graph: source files ↔ guide chapters. Parses `E-source-file-map.md` |
| `src/affected.rs` | 465 | Change propagation: given changed source files, computes affected chapters via graph traversal |
| `src/state.rs` | 632 | Fleet state management with `flock` locking, atomic writes, success-only updates |
| `src/partitioner.rs` | 523 | Section-level partitioning with disjoint write set guarantee. Tier 1/2/3 scaling |
| `src/jetty.rs` | 655 | Async Jetty API client: wave launch, adaptive polling, trajectory tracking |
| `src/merge.rs` | 505 | Git worktree-based merge: per-section sequential merge with conflict abort |
| `src/pr.rs` | 743 | PR creation (`gh` CLI) + GraphQL `updateRefs` batch branch deletion |
| `src/config.rs` | 146 | Fleet configuration: repos, Jetty params, timeouts, model routing |
| `src/lib.rs` | 16 | Module declarations |

**Runbooks** (`runbooks/`):

| File | Purpose |
|------|---------|
| `guide-sync-partitioned.md` | Chapter agent runbook: dual-repo clone, audit, fix, hard scope guard, push |
| `guide-sync-coordinator.md` | Coordinator runbook: merge chapter branches, cross-ref validation, spot-check |

**Shell wrapper**: `run-guide-sync-fleet.sh` — loads `.env`, syncs GitHub token to Jetty collection, runs orchestrator.

**Documentation** (`docs/fleet-orchestrator/`):

| File | Purpose |
|------|---------|
| `architecture.md` | ASCII + Mermaid diagrams of the full system |
| `jetty-feature-proposals.md` | 11 concrete feature proposals with API sketches |
| `research-fleet-native-primitives.md` | This document |

### Key Design Decisions (with evidence)

| Decision | Choice | Evidence |
|----------|--------|---------|
| Partitioning | Section-level, disjoint write sets | 5/5 research agents agreed: conflict-free merges by construction |
| Agent topology | 14 sections × 2-7 agents (Tier 3) | Proven ceiling is 3-5 agents per coordination level |
| Change detection | Blob SHA + bipartite graph propagation | Nx/Bazel-style affected target computation |
| Merge strategy | Sequential within sections (commutative) | Disjoint write sets make merge order irrelevant |
| State tracking | Success-only updates with file locking | Fixes optimistic update bug in existing fleet scripts |
| PR structure | Section-level (up to 14 per run) | Review is the bottleneck, not generation (DORA 2025) |

### Pain Points That Drive This Research

These are not theoretical — they are problems we hit running the fleet:

1. **GitHub as the data bus** (Track 1): Agents push branches to GitHub,
   orchestrator fetches them. 100 agents × branch push = rate limit pressure,
   5-30s latency per agent, and hundreds of API calls for what should be
   internal data transfer.

2. **Agents are blind to siblings** (Track 2): When `sec-04-a1` discovers
   `ShardSpec` was renamed to `ShardDescriptor`, agents `sec-04-a2` through
   `sec-04-a5` independently rediscover it — or worse, produce inconsistent
   fixes.

3. **Sequential phase boundaries** (Track 3): Coordinators wait for ALL
   chapter agents. If 18/20 are done but 2 are slow, 8 coordinators sit idle
   for 30+ minutes.

4. **Polling burns API calls** (Track 5): 100 agents × 30s polling = 12,000
   requests/hour. No webhooks exist.

5. **60% of orchestrator code is platform work** (all tracks): Polling,
   merging, state management, phase orchestration — all could be platform
   primitives instead of user code.

---

## Current Platform Architecture

Understanding the constraints before proposing extensions. The Jetty platform
consists of three services.

### Service Map

```
 Spot (Next.js)              Mise (FastAPI + Temporal)         MLCBakery (FastAPI)
 Web UI + proxy              Execution engine                  Metadata + provenance
 ┌──────────────┐            ┌─────────────────────┐           ┌──────────────────┐
 │ flows.jetty  │──proxy──►  │ flows-api.jetty.io  │──http──►  │ bakery (embedded │
 │ .io          │            │                     │           │ or separate)     │
 └──────────────┘            │ ┌─────────────────┐ │           └──────────────────┘
                             │ │ Temporal worker  │ │
                             │ │ (mise-tasks Q)   │ │           PostgreSQL
                             │ └────────┬────────┘ │           (entities, tasks,
                             └──────────┼──────────┘           collections, keys)
                                        │
                                        ▼
                             Daytona (cloud sandboxes)
                             ┌──────────────────────┐
                             │ codex | claude-code   │
                             │ | gemini-cli          │
                             │ 4 CPU, 8G RAM default │
                             │ Ephemeral per-step    │
                             └──────────────────────┘
```

### Mise (Execution Engine) — Where Fleet Features Live

| Component | Technology | Source File | Constraint |
|-----------|-----------|-------------|------------|
| API | FastAPI | `mise/main.py:96-128` | All endpoints in one process |
| Chat completions | OpenAI-compatible | `mise/api/endpoints/chat_completions.py:872` | Runbook mode via `jetty` block |
| Workflow engine | Temporal (gRPC) | `mise/flows/flow_workflows.py:148` | 2MB payload limit (zlib mitigated) |
| Step execution | Sequential loop | `mise/flows/flow_workflows.py:248` | `for step_name in inputs.steps` |
| Runbook step | Daytona sandbox | `mise/flows/steps/runbook.py:826-1257` | Created per-step, destroyed on completion |
| Agent install | npm CLI | `mise/flows/steps/runbook.py:92-105` | claude-code, codex, gemini-cli |
| Sandbox resources | Configurable | `mise/api/chat/models.py:25-43` | cpus (default 4), memory (default "8G") |
| Storage | Pluggable | `mise/storage/protocol.py` | S3 / GCS / local. Per-collection config |
| Trajectory DB | PostgreSQL | `mise/database/models.py:15-79` | Trajectory is atomic unit, no fleet grouping |
| Bakery dispatch | HTTP (httpx) | `mise/flows/bakery_utils.py` | Fetches task definition + collection env vars |
| Worker config | Temporal | `mise/flows/worker.py:76-89` | max 6 workflows, 10 activities, 1 task queue |
| Control flow | Step library | `mise/flows/steps/control_flow.py` | `fan_out`, `loop`, `conditional`, `map` as steps |
| Log streaming | SSE | `mise/api/endpoints/flows.py:1560` | Real-time via Temporal query |
| Metering | Per-collection | `mise/api/endpoints/metering.py` | stepsUsed / stepLimit |
| MCP servers | Injected into sandbox | `mise/flows/steps/runbook.py:1084-1134` | Agents already support MCP tools |

### MLCBakery (Metadata Service)

| Component | Source File | Purpose |
|-----------|-------------|---------|
| Task definitions | `mlcbakery/models.py:313-337` | `workflow` JSONB column (opaque to bakery) |
| Collections | `mlcbakery/api/endpoints/collections.py` | Grouping + env vars + storage config |
| API keys | `mlcbakery/models.py:405-420` | Collection-scoped, SHA-256 hashed, `mlc_` prefix |
| Storage | `mlcbakery/storage/gcp.py` | GCS only. Signed URLs, 1GB upload limit |
| Provenance | `mlcbakery/models.py:340-380` | W3C PROV model (entities, activities, agents) |
| Entity versioning | SQLAlchemy-Continuum | Content-hash-based version tracking |
| Task details endpoint | `mlcbakery/api/endpoints/task_details.py` | Enriches task with collection env vars + storage |

### Spot (Web Frontend)

| Component | Source File | Purpose |
|-----------|-------------|---------|
| Sandbox proxy | `spot/src/app/api/sandbox/completions/route.ts:19-27` | Proxies to `MISE_HOST/v1/chat/completions` |
| Agent selection | `spot/src/lib/sandbox-models.ts:16-24` | Maps model provider → agent runtime |
| Storage provider | `spot/src/lib/storage.ts` | GCS / S3 / local, with DB-backed listing |
| Trajectory viewer | `spot/src/lib/types.ts:TrajectoryData` | Web UI for execution results |
| Auth | Clerk JWT | `spot/src/middleware.ts` | Forwarded as Bearer token to Mise |

### Key Existing Extension Points

| Extension Point | Location | Current State |
|----------------|----------|--------------|
| `Step.depends_on` | `mise/flows/types.py:67` | **Exists but ignored** by the workflow engine |
| `fan_out` step | `mise/flows/steps/control_flow.py` | Launches sub-workflows within sequential pipeline |
| `StorageProtocol` | `mise/storage/protocol.py` | Pluggable — could add fleet-scoped backend |
| Temporal signals | `mise/flows/flow_workflows.py:88-106` | Used for log streaming — could carry messages |
| MCP injection | `mise/flows/steps/runbook.py:1084-1134` | Agents support MCP — messaging server injectable |
| `JettyExtension` | `mise/api/chat/models.py:25-43` | Request payload — natural place for fleet params |
| Sandbox env | `mise/flows/steps/runbook.py` env setup | Can inject `FLEET_ID`, `AGENT_INDEX`, etc. |
| SSE streaming | `mise/api/endpoints/flows.py:1560` | Workflow log streaming — extendable to fleet events |
| Collection env vars | `mlcbakery/api/endpoints/collections.py` | Secret injection mechanism exists |

### What Does Not Exist

- No concept of `fleet_id` or `run_id` grouping multiple trajectories
- No inter-agent communication channel
- No shared filesystem or artifact store between sandboxes
- No DAG scheduler (despite `depends_on` field existing in the type system)
- No fleet-level resource management or metering
- No webhook/callback for completion notification
- No speculative execution model
- No repository snapshot caching (each agent clones independently)

---

## Research Track 1: Shared State and Storage

### Problem Statement

Agents in a fleet need to share data — artifacts, intermediate results,
coordination state, discovered knowledge. Currently, they use external
services (GitHub branches, cloud storage via manual paths) as ad-hoc
communication channels. What storage primitives should the platform provide
natively?

### Design Questions

1. **Fleet-scoped artifact namespace**: How should a fleet-scoped keyspace
   be organized? Options range from a simple `{fleet_id}/{agent_id}/{path}`
   prefix convention on existing storage to a dedicated artifact service with
   metadata indexing and access control. What consistency model is appropriate?
   Strong consistency for coordination state vs. eventual consistency for
   large artifacts?

2. **Ephemeral vs. persistent shared state**: Fleet coordination state
   (which agents are done, discovered renames, cross-reference maps) is
   ephemeral — it matters during the run but not after. Artifacts (modified
   files, reports) are persistent. Should these be separate systems or
   different tiers of the same system? How does garbage collection work for
   ephemeral state when fleets crash mid-run?

3. **Copy-on-write repository snapshots**: When N agents all need the same
   repository at the same commit, each currently clones independently (N x
   5-30 seconds, N x 200MB bandwidth). Could the platform provide a
   content-addressed, copy-on-write snapshot that is prepared once and mounted
   read-only into N sandboxes? What filesystem primitives does the sandbox
   runtime (Daytona) support? Could overlay filesystems provide per-agent
   write layers on a shared read-only base?

4. **Access control within a fleet**: Should all agents in a fleet have
   equal access to shared state, or should there be role-based access?
   (e.g., coordinators can read all agents' artifacts, chapter agents can
   only read their own section.) How does this interact with the existing
   collection-level access model?

### Prior Art to Investigate

- **Temporal's workflow state model**: How does Temporal handle shared state
  between activities? What are the limits of workflow-level variables vs.
  external state stores?
- **BuildKit/Earthly layer caching**: How do container build systems share
  layers between parallel builds? Could similar content-addressed caching
  apply to repository snapshots?
- **Alluxio/JuiceFS**: Distributed caching layers for cloud storage. Could
  a caching layer between Daytona sandboxes and S3/GCS reduce redundant
  reads?
- **FUSE-based shared filesystems**: Can a FUSE mount expose fleet-scoped
  storage as a local filesystem inside sandboxes?
- **CRDTs for coordination state**: If multiple agents write to shared
  state concurrently, can conflict-free replicated data types eliminate
  coordination overhead?

---

## Research Track 2: Inter-Agent Communication

### Problem Statement

Agents operating on related subtasks benefit from real-time information
exchange. When one agent discovers a type rename, others should learn
immediately — not after a merge-and-validate cycle. What communication
primitives should the platform provide?

### Design Questions

1. **Message bus topology**: Should communication be peer-to-peer (agents
   send messages directly to other agents), pub/sub (agents publish to
   topics and subscribe to relevant ones), or mediated (messages route
   through the orchestrator)? Each has different latency, ordering, and
   delivery guarantee tradeoffs. What topology best fits the common fleet
   patterns (section-scoped communication, global broadcasts, coordinator-
   to-worker commands)?

2. **Delivery guarantees**: What level of reliability is needed? At-most-once
   (fire-and-forget, suitable for hints and suggestions), at-least-once
   (important for coordination commands), or exactly-once (required for
   state-changing operations)? How does this interact with agent restarts
   and Temporal's retry semantics?

3. **Message ordering**: Do agents need total ordering of messages (all see
   the same sequence), causal ordering (if A causes B, everyone sees A
   before B), or no ordering (best-effort, suitable for independent hints)?
   Total ordering requires consensus; causal ordering is cheaper but
   sufficient for most coordination patterns.

4. **Integration with agent runtimes**: Agents are LLM-based processes that
   communicate via stdin/stdout/tool calls, not traditional networked
   services. How should messages be delivered? Options:
   - MCP tool server injected into the sandbox (agents call a "check_messages"
     tool)
   - Filesystem-based: messages appear as files in a watched directory
   - Environment variable polling: a sidecar process writes to a known path
   - Temporal signals routed from the parent workflow to child workflows

5. **Scope and lifecycle**: Should the message bus be fleet-scoped (created
   when the fleet launches, destroyed when it completes) or persistent
   across runs (enabling cross-run knowledge transfer)? How does a fleet-
   scoped bus interact with Temporal's workflow lifecycle?

### Prior Art to Investigate

- **NATS / NATS JetStream**: Lightweight pub/sub with at-least-once delivery.
  How does it perform at 100 subscribers with low message volume?
- **Redis Streams**: Append-only log with consumer groups. Could a Redis
  instance per fleet provide scoped messaging?
- **Temporal signals and queries**: Can Temporal's built-in signal mechanism
  (already used for log streaming in Mise) carry inter-agent messages without
  adding a new dependency?
- **MCP Agent Mail**: An existing MCP server for agent-to-agent messaging.
  Could this be injected into Daytona sandboxes?
- **Kafka / Redpanda**: Overkill for fleet-scoped messaging, but their
  topic-partition model maps well to section-scoped communication.
- **Actor model (Erlang/Akka patterns)**: Each agent as an actor with a
  mailbox. How do actor systems handle the heterogeneous agent runtimes
  (claude-code, codex, gemini-cli) in Jetty?

---

## Research Track 3: Workflow DAG Scheduling

### Problem Statement

Fleets have inherent dependency structure: chapter agents must complete
before coordinators start; coordinators must complete before PRs are
created. The current sequential step loop cannot express this parallelism.
The `Step.depends_on` field exists in the type system but is ignored by the
workflow engine. How should the platform schedule dependent work?

### Design Questions

1. **DAG representation**: How should the dependency graph be expressed in
   the workflow definition? Options:
   - Implicit: infer dependencies from `*_path` expressions (if step B
     reads `stepA.outputs.text`, B depends on A)
   - Explicit: use the existing `depends_on` field on each step
   - External: a separate DAG document alongside the step list
   How does each approach interact with the existing `init_params` / `_path`
   expression system?

2. **Scheduling algorithm**: Given a DAG of steps, how should the scheduler
   dispatch work?
   - **Level-based**: group steps by dependency depth, execute each level
     in parallel (simple, may under-utilize resources)
   - **Greedy**: dispatch any step whose dependencies are met (maximizes
     parallelism, requires concurrent activity tracking)
   - **Priority-based**: assign weights (cost, criticality) and dispatch
     highest-priority ready steps first
   How does the scheduling algorithm interact with Temporal's activity
   concurrency limits (currently max 10 activities per worker)?

3. **Fan-out/fan-in as first-class patterns**: The `fan_out` control flow
   step already exists but launches sub-workflows within a sequential
   pipeline. Should fan-out become a workflow-level primitive rather than
   a step type? How would this interact with Temporal's child workflow
   model? What are the limits on the number of concurrent child workflows
   Temporal can manage?

4. **Dynamic DAGs**: Fleets may need to adapt their execution graph at
   runtime — if 30% of chapter agents fail, skip the consolidation step
   for their section. Can the DAG be modified mid-execution? How does this
   interact with Temporal's deterministic replay requirement (which forbids
   non-deterministic branching in workflow code)?

5. **Fleet as a workflow**: Should a fleet be modeled as a single Temporal
   workflow with parallel activities, a parent workflow with child workflows
   (one per agent), or a workflow of workflows? Each has different failure
   isolation, observability, and scalability characteristics.

### Prior Art to Investigate

- **Apache Airflow**: DAG-based task scheduling with dynamic task generation.
  How does Airflow handle thousands of parallel tasks?
- **Temporal child workflows**: How do Temporal child workflows interact with
  the parent's failure handling? What are the scalability limits?
- **Prefect**: Flow-based execution with automatic dependency inference from
  function signatures. How does Prefect handle fan-out/fan-in?
- **Dagger**: Container DAG execution engine. How does Dagger represent
  dependencies between containerized steps?
- **Ray**: Distributed execution framework with task dependencies and actor
  model. How does Ray's execution model compare to Temporal's?
- **Build system schedulers** (Bazel, Buck2, Nx): How do build systems
  schedule tasks in a dependency DAG with constrained parallelism?

---

## Research Track 4: Fault Tolerance and Partial Failure

### Problem Statement

In a fleet of 100 agents, partial failure is the norm, not the exception.
Research shows multi-agent LLM systems fail at 41-86.7% rates (Cemri et al.,
2025). The platform needs strategies for handling partial completion,
compensating for failed work, and maintaining consistency across a fleet
where some agents succeed and others fail.

### Design Questions

1. **Failure granularity**: What is the atomic unit of failure? A single
   agent? A section (group of agents)? The entire fleet? How does the
   failure unit interact with the state update model (which agents' results
   are persisted, which are discarded)?

2. **Compensation strategies**: When an agent fails, what should happen to
   its work? Options:
   - **Retry**: Re-launch the failed agent (simple, but may be expensive)
   - **Reassign**: Give the failed agent's work to a running agent that
     finishes early (requires dynamic task redistribution)
   - **Skip and report**: Mark the work as stale and continue (current
     approach — fast but leaves gaps)
   - **Compensate**: Undo dependent work that assumed the failed agent
     would succeed (saga pattern)
   How does each strategy interact with the state tracking model?

3. **Consistency after partial failure**: If 70 of 100 agents succeed, the
   fleet produces a partially-updated artifact. Cross-references between
   updated and stale sections may be inconsistent. What validation should
   run post-fleet? Should the platform enforce consistency invariants, or
   leave this to the orchestrator?

4. **Fleet-level health monitoring**: How should the platform expose fleet
   health to operators? Real-time dashboards, alerting thresholds (">30%
   failure rate → pause fleet"), automatic scaling of replacement agents?
   What signals indicate a fleet is in trouble before it's too late?

5. **Idempotency and resumability**: If a fleet run crashes mid-execution,
   can it be resumed? What checkpoint granularity is needed? Per-agent
   (resume only failed agents) vs. per-fleet (restart everything)?

### Prior Art to Investigate

- **Saga pattern** (Garcia-Molina & Salem, 1987): Compensating transactions
  for long-lived distributed operations. How do sagas apply to LLM agent
  work where "undo" is not always possible?
- **Temporal's retry and compensation model**: How does Temporal handle
  activity-level retries, timeouts, and workflow-level compensation?
- **Kubernetes Job completion modes**: How does K8s handle partial failure
  in indexed and parallel jobs?
- **MapReduce speculation**: How does Hadoop handle straggler tasks? Could
  speculative re-execution of slow agents reduce tail latency?
- **Circuit breaker patterns**: Should the fleet have a circuit breaker that
  halts new agent launches when failure rate exceeds a threshold?

---

## Research Track 5: Observability and Cost Management

### Problem Statement

A fleet of 100 agents consuming frontier models is expensive and opaque.
Operators need real-time visibility into what agents are doing, how much
they're spending, and whether the fleet is making progress. Current
observability is limited to polling trajectory status (running/completed/
failed) with no insight into per-agent token usage, progress, or cost.

### Design Questions

1. **Real-time fleet dashboard**: What metrics should a fleet dashboard
   show? Per-agent token usage, files modified, errors encountered,
   estimated time remaining, cost projection? How frequently should metrics
   update? How does this interact with Daytona sandbox observability?

2. **Cost attribution and budgeting**: How should costs be attributed to
   individual agents within a fleet? Should the platform enforce per-agent
   or per-fleet cost budgets that automatically stop agents when exceeded?
   How does this interact with the existing metering system (`stepsUsed`
   / `stepLimit`)?

3. **Model routing for cost optimization**: Different agents may need
   different model tiers — coordinators need frontier models for complex
   reasoning, while chapter agents doing simple text replacement could use
   cheaper models. How should the platform support per-agent model
   selection within a fleet? How does this interact with the
   `JettyExtension.agent` field?

4. **Completion event streaming**: Should the platform provide a real-time
   event stream for fleet-level events (agent started, agent completed,
   fleet progress percentage)? WebSocket, SSE, or webhook callbacks?
   The SSE infrastructure already exists for workflow log streaming —
   could it be extended?

5. **A/B testing and experimentation**: When optimizing fleet performance
   (runbook quality, model selection, partitioning strategy), how should
   the platform support experimentation? Run two fleets with different
   configurations on the same input and compare outcomes?

### Prior Art to Investigate

- **OpenTelemetry for LLM observability**: Langfuse is already integrated
  in Mise. How can fleet-level traces be structured?
- **Kubernetes HPA metrics**: How does K8s expose custom metrics for
  autoscaling decisions?
- **AWS Step Functions Map state**: How does AWS expose parallel execution
  progress and cost?
- **LLM cost tracking** (Helicone, LiteLLM proxy): How do existing LLM
  proxies attribute costs per-request?

---

## Cross-Cutting Concerns

These concerns span multiple research tracks and should be considered
holistically.

### Security and Isolation

Adding shared storage or messaging between sandboxes weakens the isolation
that makes agent execution safe. How do we preserve the security properties
of isolated sandboxes while enabling controlled communication?

- **Principle of least privilege**: Agents should only access fleet state
  relevant to their subtask, not the entire fleet's data
- **Untrusted agent output**: Agent-generated messages and artifacts should
  be treated as untrusted input by recipients
- **Credential scoping**: Fleet-scoped credentials (storage keys, messaging
  tokens) should be time-limited and scope-limited

### Backward Compatibility

Any fleet-native extensions must be backward compatible with the existing
single-agent execution model. A fleet of 1 agent should behave identically
to a standalone agent execution. The `JettyExtension` model is the natural
extension point — fleet fields should be optional.

### API Design

Fleet primitives should be exposed through the existing OpenAI-compatible
chat completions endpoint, not a separate API surface. This preserves
compatibility with existing tooling and SDKs. Fleet configuration could
live in an extended `jetty` block:

```json
{
  "jetty": {
    "runbook": true,
    "collection": "my-org",
    "task": "guide-sync",
    "fleet": {
      "fleet_id": "guide-sync-2026-04-05",
      "agent_role": "chapter-agent",
      "agent_index": 3,
      "total_agents": 20,
      "shared_storage_prefix": "fleet/guide-sync-2026-04-05/",
      "message_topic": "section-04",
      "depends_on": ["sec-04-a1", "sec-04-a2"]
    }
  }
}
```

---

## Suggested Exploration Approach

Each research track can be explored independently by different teams.
Recommended order based on impact and dependency:

```
Track 1 (Storage)  ──────────────────────────────────────────►
Track 2 (Messaging)  ─────────────────────────────────────────►
                           ╲
Track 3 (DAG Scheduling)  ──╲──────────────────────────────────►
                              ╲
Track 4 (Fault Tolerance)  ────╲───────────────────────────────►
                                ╲
Track 5 (Observability)  ────────╲─────────────────────────────►
                                  ╲
                              Integration ─────────────────────►
```

Tracks 1 and 2 are foundational — they provide the shared state and
communication channels that DAG scheduling and fault tolerance build upon.
Track 5 (observability) can proceed independently.

### Per-Track Deliverables

Each track should produce:

1. **Survey**: What exists today in the Jetty codebase (with file paths)
   that relates to this track
2. **Options analysis**: 2-3 concrete approaches with tradeoffs
3. **Prototype**: Minimal proof-of-concept demonstrating the highest-leverage
   option
4. **Integration design**: How the prototype connects to the existing Mise
   architecture (specific files, new fields, migration path)
5. **Evaluation criteria**: How to measure whether the primitive actually
   helps fleet operators (latency reduction, code eliminated, failure rate
   improvement)

---

## Appendix: Complete Source Code Index

### Jetty Platform (Mise)

| File | Purpose | Fleet Relevance |
|------|---------|----------------|
| `/Users/ahrav/Projects/mise/mise/main.py:96-128` | API route registration | All fleet endpoints would be registered here |
| `/Users/ahrav/Projects/mise/mise/api/endpoints/chat_completions.py:872` | Chat completions entry point | Fleet launch requests arrive here |
| `/Users/ahrav/Projects/mise/mise/api/endpoints/chat_completions.py:468` | `_prepare_runbook` | Runbook resolution + task auto-creation |
| `/Users/ahrav/Projects/mise/mise/api/endpoints/chat_completions.py:231` | `_get_or_create_task` | Auto-creates tasks in Bakery on first use |
| `/Users/ahrav/Projects/mise/mise/api/chat/models.py:25-43` | `JettyExtension` model | **Primary extension point** for fleet params |
| `/Users/ahrav/Projects/mise/mise/api/chat/handlers.py:163-169` | `_infer_agent_from_model` | Maps model names to agent runtimes |
| `/Users/ahrav/Projects/mise/mise/flows/flow_workflows.py:37` | `FlowWorkflow` class | Temporal workflow — where DAG scheduling would replace sequential loop |
| `/Users/ahrav/Projects/mise/mise/flows/flow_workflows.py:148` | `FlowWorkflow.run` | The sequential step loop (line 248) |
| `/Users/ahrav/Projects/mise/mise/flows/flow_workflows.py:88-106` | Temporal signals | Log event signals — extendable for inter-agent messages |
| `/Users/ahrav/Projects/mise/mise/flows/flow_workflows.py:19-34` | `FlowWorkflowInput` | Workflow input dataclass — needs fleet fields |
| `/Users/ahrav/Projects/mise/mise/flows/activities.py:275-350` | `flow_step_harness` | Step execution activity — dispatches to step library |
| `/Users/ahrav/Projects/mise/mise/flows/steps/runbook.py:826-1257` | `RunbookStep.__call__` | Daytona sandbox creation + agent execution |
| `/Users/ahrav/Projects/mise/mise/flows/steps/runbook.py:92-105` | Agent definitions | claude-code, codex, gemini-cli configs |
| `/Users/ahrav/Projects/mise/mise/flows/steps/runbook.py:1084-1134` | MCP server injection | Agents already support MCP tools |
| `/Users/ahrav/Projects/mise/mise/flows/steps/runbook.py:924-1006` | File upload/download | How files move between storage and sandbox |
| `/Users/ahrav/Projects/mise/mise/flows/steps/control_flow.py` | `fan_out`, `loop`, `conditional`, `map` | Existing control flow primitives |
| `/Users/ahrav/Projects/mise/mise/flows/types.py:67` | `Step.depends_on` | **Exists but unused** by the workflow engine |
| `/Users/ahrav/Projects/mise/mise/flows/types.py:82-159` | `Trajectory` type | Would need `fleet_id` field |
| `/Users/ahrav/Projects/mise/mise/flows/step_library.py:16-35` | `STEP_LIBRARY` | Step name → function mapping |
| `/Users/ahrav/Projects/mise/mise/flows/bakery_utils.py` | Bakery HTTP client | Fetches task definitions + env vars |
| `/Users/ahrav/Projects/mise/mise/flows/bakery_utils.py:73` | Error wrapping | **Bug**: Bakery 500s wrapped as 400 |
| `/Users/ahrav/Projects/mise/mise/flows/bakery_utils.py:138` | `_setup_workflow_input` | Creates Temporal workflow input |
| `/Users/ahrav/Projects/mise/mise/flows/trajectory_utils.py` | Trajectory save/load | All trajectory persistence goes through here |
| `/Users/ahrav/Projects/mise/mise/flows/worker.py:76-89` | Worker config | max 6 workflows, 10 activities, 10min shutdown |
| `/Users/ahrav/Projects/mise/mise/flows/workflow_launcher.py` | `WorkflowLauncher` | Could spawn fleet child workflows |
| `/Users/ahrav/Projects/mise/mise/flows/workflow_utils.py:12-41` | Zlib compression | Payloads compressed for Temporal 2MB limit |
| `/Users/ahrav/Projects/mise/mise/storage/protocol.py` | `StorageProtocol` | **Pluggable storage interface** — fleet storage would implement this |
| `/Users/ahrav/Projects/mise/mise/storage/factory.py:125-150` | Storage factory | Creates S3/GCS/local backends from config |
| `/Users/ahrav/Projects/mise/mise/storage/s3.py` | S3 backend | boto3-based |
| `/Users/ahrav/Projects/mise/mise/storage/gcs.py` | GCS backend | obstore-based |
| `/Users/ahrav/Projects/mise/mise/database/models.py:15-79` | Trajectory DB model | PostgreSQL index/cache — needs `fleet_id` column |
| `/Users/ahrav/Projects/mise/mise/api/endpoints/trajectory.py` | Trajectory API | List/get/update trajectories |
| `/Users/ahrav/Projects/mise/mise/api/endpoints/trajectory_db.py` | DB-backed trajectory API | Complex queries with filters |
| `/Users/ahrav/Projects/mise/mise/api/endpoints/flows.py:1560` | SSE log stream | Real-time event streaming infrastructure |
| `/Users/ahrav/Projects/mise/mise/api/endpoints/flows.py:412` | File download | Get artifacts from storage |
| `/Users/ahrav/Projects/mise/mise/api/endpoints/sandbox.py:29` | Sandbox upload | File upload to sandbox storage (50MB limit) |
| `/Users/ahrav/Projects/mise/mise/api/endpoints/metering.py` | Usage metering | Per-collection resource tracking |

### Jetty Platform (MLCBakery)

| File | Purpose | Fleet Relevance |
|------|---------|----------------|
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/main.py` | FastAPI entry point | 10 route groups under `/api/v1` |
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/models.py:313-337` | `Task` model | `workflow` JSONB — fleet topology could live here |
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/models.py:384-402` | `Agent` model | Provenance metadata, not running agents |
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/models.py:340-380` | `EntityRelationship` | Provenance DAG — could track fleet lineage |
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/models.py:405-420` | `APIKey` model | Collection-scoped, SHA-256 hashed |
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/api/endpoints/collections.py` | Collection CRUD | env vars, storage config |
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/api/endpoints/task_details.py` | Task details | Enriches task with collection env vars + storage |
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/api/endpoints/tasks.py:255-286` | Task fetch | **Where the guide-sync corruption caused 500** |
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/schemas/task.py:50-59` | `TaskResponse` | Pydantic model — validation failure caused our bug |
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/storage/gcp.py` | GCS storage | Signed URLs, race-safe uploads |
| `/Users/ahrav/Projects/mlcbakery/mlcbakery/database.py:25-33` | DB connection pool | 5 base + 10 overflow, 30s timeout |

### Jetty Platform (Spot)

| File | Purpose | Fleet Relevance |
|------|---------|----------------|
| `/Users/ahrav/Projects/spot/src/app/api/sandbox/completions/route.ts:19-27` | Sandbox proxy | Fleet launches would route through here |
| `/Users/ahrav/Projects/spot/src/lib/sandbox-models.ts:16-24` | Agent selection | Model → agent runtime mapping |
| `/Users/ahrav/Projects/spot/src/lib/sandbox-types.ts:52-58` | `JettyExtension` (TS) | TypeScript mirror of Mise's `JettyExtension` |
| `/Users/ahrav/Projects/spot/src/lib/storage.ts:30-141` | Storage provider | Fleet storage browser would be built here |
| `/Users/ahrav/Projects/spot/src/lib/types.ts:TrajectoryData` | Trajectory model | Needs `fleet_id`, `fleet_metadata` |
| `/Users/ahrav/Projects/spot/src/lib/mise-client.ts:288-315` | Mise HTTP client | Fleet execution methods would be added here |

### Fleet Orchestrator Experiment (gossip-rs)

| File | Purpose |
|------|---------|
| `/Users/ahrav/Projects/gossip-rs/crates/fleet-orchestrator/src/main.rs` | 5-phase pipeline (880 lines) |
| `/Users/ahrav/Projects/gossip-rs/crates/fleet-orchestrator/src/graph.rs` | Dependency graph builder (476 lines) |
| `/Users/ahrav/Projects/gossip-rs/crates/fleet-orchestrator/src/affected.rs` | Change propagation (465 lines) |
| `/Users/ahrav/Projects/gossip-rs/crates/fleet-orchestrator/src/state.rs` | Locked state manager (632 lines) |
| `/Users/ahrav/Projects/gossip-rs/crates/fleet-orchestrator/src/partitioner.rs` | Disjoint partitioning (523 lines) |
| `/Users/ahrav/Projects/gossip-rs/crates/fleet-orchestrator/src/jetty.rs` | Async Jetty client (655 lines) |
| `/Users/ahrav/Projects/gossip-rs/crates/fleet-orchestrator/src/merge.rs` | Git worktree merge (505 lines) |
| `/Users/ahrav/Projects/gossip-rs/crates/fleet-orchestrator/src/pr.rs` | PR + branch cleanup (743 lines) |
| `/Users/ahrav/Projects/gossip-rs/crates/fleet-orchestrator/src/config.rs` | Configuration (146 lines) |
| `/Users/ahrav/Projects/gossip-rs/crates/fleet-orchestrator/Cargo.toml` | Dependencies: tokio, reqwest, petgraph, git2, clap |
| `/Users/ahrav/Projects/gossip-rs/runbooks/guide-sync-partitioned.md` | Chapter agent runbook (434 lines) |
| `/Users/ahrav/Projects/gossip-rs/runbooks/guide-sync-coordinator.md` | Coordinator agent runbook |
| `/Users/ahrav/Projects/gossip-rs/run-guide-sync-fleet.sh` | Shell wrapper |
| `/Users/ahrav/Projects/gossip-rs/run-doc-rigor-fleet.sh` | Existing fleet script (comparison reference) |
| `/Users/ahrav/Projects/gossip-rs/run-audit-fleet.sh` | Existing fleet script (comparison reference) |
| `/Users/ahrav/Projects/gossip-rs/.fleet-state.json` | Persistent state ledger |
| `/Users/ahrav/Projects/gossip-rs/docs/fleet-orchestrator/architecture.md` | System architecture diagrams |
| `/Users/ahrav/Projects/gossip-rs/docs/fleet-orchestrator/jetty-feature-proposals.md` | 11 feature proposals with API sketches |

### Deep Research Artifacts

| File | Contents |
|------|---------|
| `/Users/ahrav/Projects/gossip-rs/.claude/plans/melodic-percolating-charm.md` | Approved implementation plan |
| `/Users/ahrav/Projects/gossip-rs/.claude/plans/melodic-percolating-charm-agent-a553482c038abb3b8.md` | Research synthesis: 35 findings, risk register, consensus matrix |
| `/Users/ahrav/Projects/gossip-rs/.claude/plans/melodic-percolating-charm-agent-a3afbd1bdfde0540a.md` | Agent 1: Foundational Theory (15 findings) |
| `/Users/ahrav/Projects/gossip-rs/.claude/plans/melodic-percolating-charm-agent-af35650905e08e47c.md` | Agent 2: Production Systems (16 findings) |
| `/Users/ahrav/Projects/gossip-rs/.claude/plans/melodic-percolating-charm-agent-a5fd00209eb1e4725.md` | Agent 3: Failure Modes (13 findings) |
| `/Users/ahrav/Projects/gossip-rs/.claude/plans/melodic-percolating-charm-agent-a7aff961600aea707.md` | Agent 4: Tooling & Ecosystem (14 findings) |
| `/Users/ahrav/Projects/gossip-rs/.claude/plans/melodic-percolating-charm-agent-a31d2ba7fd2555d4d.md` | Agent 5: Industry Practice (14 findings) |
| `/Users/ahrav/Projects/gossip-rs/.claude/plans/melodic-percolating-charm-agent-a687308967b5a777f.md` | Integrator: Full implementation plan |

### Academic and Industry References

| Reference | Relevance |
|-----------|-----------|
| "Why Do Multi-Agent LLM Systems Fail?" (Cemri et al., 2025, arXiv:2503.13657) | 79% of failures from specification/coordination |
| Google SWE Book Ch. 22 — Rosie (abseil.io/resources/swe-book/html/ch22.html) | Large-scale automated code modification patterns |
| Shopify Merge Queue (shopify.engineering/successfully-merging-work-1000-developers) | 1000+ developer merge orchestration |
| "Build Systems a la Carte" (Mokhov et al., ICFP 2018) | Formal framework for incremental build/sync systems |
| Calvin (Thomson et al., SIGMOD 2012) | Deterministic ordering for conflict-free parallel execution |
| Agentic Drift (dev.to/helgesverre) | Non-linear integration cost scaling with agent count |
| DORA 2025 Report (dora.dev/research/2025/dora-report) | AI-generated code creates 154% larger PRs |
| Addy Osmani: Code Agent Orchestra (addyosmani.com/blog/code-agent-orchestra) | 3-5 agent sweet spot, file ownership patterns |
| Buck2 DICE Engine (buck2.build/docs/insights_and_knowledge/modern_dice) | Content-hash invalidation with skip-if-same-values |
| GitHub API Rate Limits (docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) | Hard constraints: 100 concurrent, 80 content-generating/min |
| Mergify Speculative Checks (docs.mergify.com/merge-queue/speculative-checks) | Cumulative merge testing with n-ary failure bisection |
| OpenHands Refactor SDK (openhands.dev/blog/automating-massive-refactors-with-parallel-agents) | Integration branch pattern for parallel agents |
