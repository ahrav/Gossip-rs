# Fleet Orchestrator Architecture

Guide-sync fleet orchestration system for synchronizing the
`gossip-rs-learning-guide` (99 chapters, 14 sections) with the `gossip-rs`
source codebase using 20-100 parallel agents.

## System Overview

Three execution zones: the local machine runs the Rust orchestrator binary,
Jetty Cloud hosts sandboxed agents, and GitHub stores repos/branches/PRs.

```
 LOCAL MACHINE                    JETTY CLOUD                        GITHUB
 (fleet-orchestrator)             (sandboxed agents)                 (repos + branches)
 ========================         ========================           ========================

 Phase 0: Graph + Detect
 +----------------------+
 | Parse E-source-file- |
 | map.md -> petgraph   |
 |                      |
 | git ls-tree (blobs)  |--- reads ------------------------------>  gossip-rs (source)
 | Compare vs state     |                                           origin/main @ BASE_SHA
 | Propagate -> affected|
 | chapters             |
 +----------+-----------+
            |
            | affected chapters
            | grouped by section
            v
 Phase 1: Partition + Launch
 +----------------------+         +-------------------------+
 | Partition by section |         |  WAVE 1 (15 agents)     |
 | Tier 3: ceil(N/3)   |         | +-----++-----++-----+   |
 | agents per section   |-- POST -| |ch-01||ch-02||ch-03|   |
 |                      |  /v1/   | | 02  || 02  || 02  |   |
 | Substitute runbook   |  chat/  | +--+--++--+--++--+--+   |
 | template per agent   |  compl. |    |      |      |      |
 |                      |         | +--+--++--+--++--+--+   |
 | Wave launch:         |         | |ch-01||ch-02||...  |   |
 |  15/wave, 2s delay   |         | | 04  || 04  ||     |   |
 +----------+-----------+         | +--+--++--+--++--+--+   |
            |                     |    :      :      :      |
            |                     +----+------+------+------+
            |                          |      |      |
            |                     +----+------+------+------+
            |                     |  WAVE 2 (5 agents)      |
            |              2s --> | +-----++-----++-----+   |
            |              delay  | |ch-01||ch-02||ch-03|   |
            |                     | | 07  || 07  || 08  |   |
            |                     | +--+--++--+--++--+--+   |
            |                     +----+------+------+------+
            |                          |      |      |
            |                          v      v      v
            |                     EACH AGENT SANDBOX:
            |                     +----------------------+
            |                     | 1. gh clone source   |
            |                     |    @ pinned SHA      |--- clone -->  gossip-rs
            |                     |    (READ ONLY)       |              (read only)
            |                     |                      |
            |                     | 2. gh clone guide    |--- clone -->  gossip-rs-
            |                     |    create branch     |              learning-guide
            |                     |                      |
            |                     | 3. Audit chapters:   |
            |                     |    - REMOVED types   |
            |                     |    - RENAMED items   |
            |                     |    - STALE_CODE      |
            |                     |    - WRONG_SIGNATURE |
            |                     |    - STALE_XREF      |
            |                     |                      |
            |                     | 4. Fix drift in      |
            |                     |    assigned chapters  |
            |                     |                      |
            |                     | 5. Scope guard check |
            |                     |    (HARD: unstage    |
            |                     |     non-manifest)    |
            |                     |                      |
            |                     | 6. git push branch   |--- push --->  guide-sync/
            |                     +----------------------+              sec-04-a1/
            |                                                           {run_id}
 Phase 2a: Poll Chapter Agents
 +----------------------+
 | tokio::join! poll    |-- GET -->  Jetty trajectory API
 | all trajectories     |<- status - {completed|running|failed}
 |                      |
 | Adaptive backoff:    |
 |  60s -> 30s when     |
 |  >50% done           |
 +----------+-----------+
            |
            | all chapter agents done
            v
 Phase 2b: Launch Coordinators (TIER 3 ONLY)
 +----------------------+         +-------------------------+
 | 1 coordinator per    |         |  COORDINATOR AGENTS     |
 | section (up to 8)    |         |                         |
 |                      |-- POST -| +-------+  +-------+   |
 | Uses coordinator     |  /v1/   | |coord  |  |coord  |   |
 | runbook template     |  chat/  | | sec-00|  | sec-01|   |
 |                      |  compl. | +---+---+  +---+---+   |
 | Can use different    |         |     :          :        |
 | model (frontier)     |         | +-------+  +-------+   |
 +----------+-----------+         | |coord  |  |coord  |   |
            |                     | | sec-07|  | sec-08|   |
            |                     | +---+---+  +---+---+   |
            |                     +-----+----------+-------+
            |                           |          |
            |                           v          v
            |                     EACH COORDINATOR:
            |                     +----------------------+
            |                     | 1. Fetch chapter     |
            |                     |    agent branches    |<- fetch ---  guide-sync/
            |                     |                      |             sec-04-a{1..5}/
            |                     | 2. Merge into        |             {run_id}
            |                     |    section branch    |
            |                     |                      |
            |                     | 3. Cross-ref check:  |
            |                     |    [Chapter N-M]     |
            |                     |    links valid?      |
            |                     |                      |
            |                     | 4. Code example      |
            |                     |    spot-check (10%)  |
            |                     |                      |
            |                     | 5. Push section      |--- push --->  guide-sync/
            |                     |    integration       |              section-04/
            |                     |    branch            |              {run_id}
            |                     +----------------------+
            |
            | poll coordinators
            v
 Phase 3: Merge + PR
 +----------------------+
 | git worktree add     |
 | (guide repo)         |
 |                      |
 | Fetch section        |<- fetch --------------------------------  guide-sync/
 | integration branches |                                           section-{00..08}/
 |                      |                                           {run_id}
 | Tier 2/3: create     |
 | per-section PRs      |--- gh pr create ----------------------->  PR per section
 |                      |                                           (up to 14)
 | GraphQL updateRefs   |--- mutation ----------------------------  delete agent +
 | batch branch cleanup |                                           section branches
 |                      |
 | git worktree remove  |
 +----------+-----------+
            |
            v
 Phase 4: State Update
 +----------------------+
 | flock .fleet-state.  |
 | json.lock            |
 |                      |
 | SUCCESS ONLY:        |
 |  completed + merged  |
 |  -> status: current  |
 |                      |
 | FAILED agents:       |
 |  -> status: stale    |
 |  (retried next run)  |
 |                      |
 | Atomic write:        |
 |  .tmp -> rename      |
 +----------------------+
```

## Tier 3 Hierarchy

Two-level agent hierarchy matching the guide's 14-section structure.
Coordinators validate cross-references between chapters that different
agents modified within the same section.

```
                    +----------------------+
                    |    ORCHESTRATOR      |
                    |    (local machine)   |
                    +----------+-----------+
                               |
              launches         |          polls + creates PRs
         +---------------------+---------------------+
         |                     |                     |
         v                     v                     v
 +---------------+   +---------------+     +---------------+
 |  coord-00     |   |  coord-04     | ... |  coord-08     |
 |  (Jetty)      |   |  (Jetty)      |     |  (Jetty)      |
 |               |   |               |     |               |
 | merge + xref  |   | merge + xref  |     | merge + xref  |
 | validate      |   | validate      |     | validate      |
 +-------+-------+   +-------+-------+     +-------+-------+
         |            +------+|+------+------+------+|
         |            |      ||      |      |      ||
         v            v      vv      v      v      vv
 +----------+  +--------++--------++--------++--------++--------+
 | sec-00   |  |sec-04  ||sec-04  ||sec-04  ||sec-04  ||sec-04  |
 | 3 chaps  |  |  -a1   ||  -a2   ||  -a3   ||  -a4   ||  -a5   |
 | (Jetty)  |  |3 chaps ||3 chaps ||3 chaps ||2 chaps ||2 chaps |
 +----------+  +--------++--------++--------++--------++--------+
                   |          |        |         |         |
                   v          v        v         v         v
               04-01      04-02     04-03     04-04     04-06
               04-06      04-08     04-09     04-10     04-11
               04-11      04-13     04-14

              (disjoint chapter ownership -- no file overlap)
```

## Pipeline Sequence

```mermaid
sequenceDiagram
    participant O as Orchestrator<br/>(local)
    participant J as Jetty API
    participant CA as Chapter Agents<br/>(sandboxes)
    participant CO as Coordinator Agents<br/>(sandboxes)
    participant GH as GitHub

    Note over O: Phase 0: Graph + Change Detection
    O->>O: Parse E-source-file-map.md
    O->>GH: git ls-tree (blob SHAs)
    GH-->>O: current blob SHAs
    O->>O: Compare vs .fleet-state.json
    O->>O: Propagate changes through graph
    O->>O: Partition by section + tier

    Note over O: Phase 1: Launch Chapter Agents
    loop Wave N (15 agents, 2s delay)
        O->>J: POST /v1/chat/completions (runbook + manifest)
        J-->>O: trajectory_id
    end

    Note over O,CA: Phase 2a: Chapter Agents Execute
    par Each sandbox
        CA->>GH: clone gossip-rs @ pinned SHA (read)
        CA->>GH: clone learning-guide (write)
        CA->>CA: Audit chapters vs source code
        CA->>CA: Fix drift (REMOVED, RENAMED, STALE_CODE, ...)
        CA->>CA: Scope guard: validate write_set
        CA->>GH: push guide-sync/{agent-id}/{run-id}
    end

    loop Adaptive polling (60s → 30s)
        O->>J: GET trajectory status
        J-->>O: completed / running / failed
    end

    Note over O,CO: Phase 2b: Launch Coordinators (Tier 3)
    loop Per section
        O->>J: POST /v1/chat/completions (coordinator runbook)
        J-->>O: coordinator trajectory_id
    end

    par Each coordinator sandbox
        CO->>GH: fetch chapter agent branches
        CO->>CO: Merge into section branch
        CO->>CO: Cross-reference validation
        CO->>CO: Code example spot-check (10%)
        CO->>GH: push guide-sync/section-{id}/{run-id}
    end

    loop Poll coordinators
        O->>J: GET coordinator status
        J-->>O: completed / failed
    end

    Note over O: Phase 3: Merge + PR
    O->>O: git worktree add (guide repo)
    O->>GH: fetch section integration branches
    O->>O: merge sections locally

    alt Tier 1
        O->>GH: create 1 consolidated PR
    else Tier 2/3
        loop Per section
            O->>GH: push section branch
            O->>GH: create section PR
        end
    end

    O->>GH: GraphQL updateRefs (batch delete branches)
    O->>O: git worktree remove

    Note over O: Phase 4: State Update
    O->>O: flock .fleet-state.json
    O->>O: Mark successful chapters "current"
    O->>O: Mark failed chapters "stale" (retry next run)
    O->>O: Atomic write (.tmp → rename)
```

## State Tracking

Change detection flows through a bipartite dependency graph. When source
files change, affected chapters are computed via graph traversal with early
cutoff for chapters already synced to the current source SHA.

```mermaid
graph LR
    subgraph "Source Files (gossip-rs)"
        S1["identity/types.rs"]
        S2["identity/canonical.rs"]
        S3["coordination/lease.rs"]
        S4["coordination/run.rs"]
        S5["frontier/range.rs"]
    end

    subgraph "Guide Chapters (learning-guide)"
        C1["01-04: Type-Driven Design"]
        C2["02-02: Canonical Encoding"]
        C3["02-04: Identity Newtypes"]
        C4["04-02: Leases and Fencing"]
        C5["04-03: Starting a Scan"]
        C6["05-01: Key Encoding"]
    end

    S1 --> C1
    S1 --> C3
    S2 --> C2
    S2 --> C3
    S3 --> C4
    S3 --> C5
    S4 --> C5
    S5 --> C6

    style S1 fill:#f96,stroke:#333
    style S3 fill:#f96,stroke:#333
```

> In this example, if `types.rs` and `lease.rs` change (highlighted), the
> affected chapters are 01-04, 02-04, 04-02, and 04-03 — computed by
> traversing edges from the changed source nodes.

## Scaling Tiers

```mermaid
graph TD
    subgraph "Tier 1: 14 agents"
        T1O[Orchestrator] --> T1A1[sec-00<br/>3 chapters]
        T1O --> T1A2[sec-01<br/>4 chapters]
        T1O --> T1A3[sec-02<br/>9 chapters]
        T1O --> T1A4["... (1 agent per section)"]
    end

    subgraph "Tier 2: 20-50 agents"
        T2O[Orchestrator] --> T2S1[sec-00<br/>1 agent]
        T2O --> T2S2["sec-04 (3 agents)"]
        T2S2 --> T2A1[sec-04-a1<br/>5 chaps]
        T2S2 --> T2A2[sec-04-a2<br/>5 chaps]
        T2S2 --> T2A3[sec-04-a3<br/>4 chaps]
    end

    subgraph "Tier 3: 50-100 agents"
        T3O[Orchestrator] --> T3C1[coord-00]
        T3O --> T3C2[coord-04]
        T3C1 --> T3CA1[sec-00<br/>3 chaps]
        T3C2 --> T3CB1[sec-04-a1<br/>3 chaps]
        T3C2 --> T3CB2[sec-04-a2<br/>3 chaps]
        T3C2 --> T3CB3[sec-04-a3<br/>3 chaps]
        T3C2 --> T3CB4[sec-04-a4<br/>2 chaps]
        T3C2 --> T3CB5[sec-04-a5<br/>2 chaps]
    end
```

## Data Flow Summary

| Step | From | To | Mechanism |
|------|------|----|-----------|
| Read blob SHAs | Local | GitHub | `git ls-tree` |
| Read state | Local | `.fleet-state.json` | `flock` + JSON |
| Build graph | Local | petgraph | Parse `E-source-file-map.md` |
| Launch agents | Local | Jetty | `POST /v1/chat/completions` |
| Clone repos | Jetty sandbox | GitHub | `gh repo clone` |
| Audit + fix | Jetty sandbox | Jetty sandbox | Read source, edit guide |
| Push branch | Jetty sandbox | GitHub | `git push` |
| Poll status | Local | Jetty | `GET /api/v1/db/trajectory/...` |
| Merge branches | Local | Local worktree | `git fetch` + `git merge` |
| Create PRs | Local | GitHub | `gh pr create` |
| Clean branches | Local | GitHub | GraphQL `updateRefs` mutation |
| Update state | Local | `.fleet-state.json` | `flock` + atomic rename |
