## Task Management

This project uses `bd` (Beads) for issue tracking. Issues live in `.beads/`.

At session start: run `bd ready` to find work.
Track status with `bd update <id> --status in_progress`.
At session end: close finished work, file new issues, run `bd sync`. Do NOT commit.

For graph-aware triage: `bv --robot-triage` (never bare `bv`).

When working in plan mode, always include bd status updates
in the plan (update to in_progress at start, close at end).

## Rust Code Modification Workflow

After modifying Rust code, ALWAYS run these steps:

1. `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features`
2. Run `/doc-rigor` skill on the new code to keep documentation updated
3. If adding new components, update relevant docs: `docs/gossip-coordination/coordination-testing.md`, `docs/gossip-coordination/simulation-harness.md`, `docs/gossip-coordination/boundary-2-coordination.md`

<!-- zero-alloc-hot-path-v1 -->

## Allocation Policy (Tiered) — MANDATORY

Use an operationally tiered policy instead of blanket no-allocation rules.

### Tiers

- **HOT**: per-shard/per-claim/per-tick steady-state loops.
- **WARM**: frequent read/query/admin operations outside inner mutation loops.
- **COLD**: startup, registration, setup/teardown, and test-support helpers.

### Rules

1. **HOT paths remain allocation-silent where practical.**
   Keep pooled/slab-backed data and caller-owned reusable scratch on true
   steady-state paths (`acquire_and_restore_into`, `checkpoint`, `complete`,
   claim loop internals).
2. **WARM/COLD paths optimize for simplicity first.**
   Prefer straightforward local allocation over preallocation-only API contracts
   when complexity tax is high and measurable regressions are absent.
3. **No panic-on-undersized-caller-buffer contracts for query APIs.**
   `list_shards_into` and `collect_claim_candidates_into` may grow caller
   vectors as needed.
4. **Registration keeps atomicity, not scratch plumbing.**
   `register_shards` must perform fallible preflight before shard-map mutation
   and must roll back staged records on allocation failure.
5. **Single allocation-failure shape for register_shards.**
   Use `RegisterShardsError::ResourceExhausted { resource }` everywhere.
6. **No parallel legacy/new surfaces.**
   Breaking changes are applied in one pass; remove superseded allocation
   behavior instead of preserving compatibility layers.

### Existing Infrastructure (use these, don't reinvent)

| Type | Location | Purpose |
|------|----------|---------|
| `ByteSlab` / `ByteSlot` | `gossip-stdx/src/byte_slab.rs` | Core pre-allocated byte pool |
| `PooledShardSpec` | `coordination/pooled.rs` | Slab-backed shard spec fields |
| `PooledCursor` | `coordination/pooled.rs` | Slab-backed cursor fields |
| `PooledSpawned` | `coordination/pooled.rs` | Slab-backed lineage storage |
| `AcquireScratch` / `FixedBuf` | `coordination/error.rs` | Reusable fixed-capacity scratch |
| `InlineVec<T, N>` | `gossip-stdx/src/inline_vec.rs` | Stack-first small collection |
| `RingBuffer<T, N>` | `gossip-stdx/src/ring_buffer.rs` | Fixed-capacity circular queue |

### Enforcement

- Hot-path regressions are benchmark-gated: no >5% median regression without
  explicit documented justification.
- PRs that introduce avoidable hot-path heap allocation or legacy dual-path
  allocation behavior will be rejected.

<!-- end-zero-alloc-hot-path -->

<!-- bv-agent-instructions-v1 -->

### Using bv as an AI sidecar

bv is a graph-aware triage engine for Beads projects (.beads/beads.jsonl). Instead of parsing JSONL or hallucinating graph traversal, use robot flags for deterministic, dependency-aware outputs with precomputed metrics (PageRank, betweenness, critical path, cycles, HITS, eigenvector, k-core).

**Scope boundary:** bv handles _what to work on_ (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use [MCP Agent Mail](https://github.com/Dicklesworthstone/mcp_agent_mail).

**⚠️ CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

#### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns everything you need in one call:

- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

bv --robot-triage # THE MEGA-COMMAND: start here
bv --robot-next # Minimal: just the single top pick + claim command

# Token-optimized output (TOON) for lower LLM context usage:

bv --robot-triage --format toon
export BV_OUTPUT_FORMAT=toon
bv --robot-next

#### Other Commands

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS (hubs/authorities), eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level` (healthy\|warning\|critical), `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels by: (pagerank × staleness × block_impact) / velocity |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations: `stats`, `histories` (per-bead events/commits/milestones), `commit_index` |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles introduced/resolved |

**Other Commands:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions, cycle breaks |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Self-contained interactive HTML visualization |

#### Scoping & Filtering

bv --robot-plan --label backend # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30 # Historical point-in-time
bv --recipe actionable --robot-plan # Pre-filter: ready to work (no blockers)
bv --recipe high-impact --robot-triage # Pre-filter: top PageRank scores
bv --robot-triage --robot-triage-by-track # Group by parallel work streams
bv --robot-triage --robot-triage-by-label # Group by domain

#### Understanding Robot Output

**All robot JSON includes:**

- `data_hash` — Fingerprint of source beads.jsonl (verify consistency across calls)
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`; contains ref and resolved SHA

**Two-step analysis:**

- **Immediate pass (instant):** degree, topo sort, density — always available immediately
- **Deferred pass (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles — check `status` flags

**For large graphs (>500 nodes):** Some metrics may be approximated or skipped. Always check `status`.

#### jq Quick Reference

bv --robot-triage | jq '.quick_ref' # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]' # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact' # Best unblock target
bv --robot-insights | jq '.status' # Check metric readiness
bv --robot-insights | jq '.Cycles' # Circular deps (must fix!)
bv --robot-label-health | jq '.results.labels[] | select(.health_level == "critical")'

**Performance:** Immediate pass is instant; deferred pass is async (500ms timeout). Prefer `--robot-plan` over `--robot-insights` when speed matters. Results cached by data hash.

Use bv instead of parsing beads.jsonl—it computes PageRank, critical paths, cycles, and parallel tracks deterministically.

---

## Beads Workflow Integration

This project uses [beads_viewer](https://github.com/Dicklesworthstone/beads_viewer) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
bd ready              # Show issues ready to work (no blockers)
bd list --status=open # All open issues
bd show <id>          # Full issue details with dependencies
bd create --title="..." --type=task --priority=2
bd update <id> --status=in_progress
bd close <id> --reason="Completed"
bd close <id1> <id2>  # Close multiple issues at once
bd sync --flush-only  # Export beads to JSONL (no git ops)
```

### Workflow Pattern

1. **Start**: Run `bd ready` to find actionable work
2. **Claim**: Use `bd update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `bd close <id>`
5. **Sync**: Always run `bd sync --flush-only` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `bd ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `bd dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run `bd sync --flush-only` to persist beads state.**

Do NOT stage, commit, or push code changes. Leave that to the user.

### Best Practices

- Check `bd ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `bd create` when you discover tasks
- Use descriptive titles and set appropriate priority/type

<!-- end-bv-agent-instructions -->

<!-- task-quality-standard-v1 -->

## Task Quality Standard — MANDATORY for All Task Creation

Every beads task must be **self-contained**: an LLM agent reading it should
have 90% of the information needed to complete it. The remaining 10% must
have explicit pointers to where to look.

### How to Create Tasks

Use `/create-task` for all task creation. It auto-researches the codebase
and produces a complete task description.

    /create-task "Fix off-by-one in window boundary check" --type=bug --priority=1
    /create-task --quick "..." --type=task --priority=2
    /create-task --from-plan docs/plans/2026-02-23-feature-v3.md --step=3

### Mandatory Sections (ALL Tasks)

1. **Context** — Why this task exists
2. **Current State** — What exists today (with code snippets and file:line refs)
3. **Desired State** — What should exist after
4. **Implementation Guidance** — Files to modify, patterns to follow, utilities to reuse
5. **Code References** — Inline snippets of relevant current code
6. **Related Work** — Links to related beads tasks (or "None found")
7. **Acceptance Criteria** — Specific, verifiable conditions (always include cargo test/fmt/clippy)
8. **Pointers** — Where to look for the remaining 10%

### Never Do

- Create a task with no description
- Write "see review for details" or "see PR #N" instead of inlining context
- Reference code without file paths and line numbers
- Write acceptance criteria like "it works" — must be specific and verifiable
- Skip the Related Work search — always check for existing related/duplicate tasks

### Enforcement

Tasks created with empty or stub descriptions will be flagged during review.
When creating tasks outside `/create-task` (e.g., inside `/execute-review-findings`),
include all mandatory sections in the description.

<!-- end-task-quality-standard -->

<!-- duplication-prevention-v1 -->

## Duplication Prevention — MANDATORY Pre-Coding Check

**Before writing ANY new function, struct, trait, method, or module, you MUST
verify the functionality does not already exist in the codebase.**

This is non-negotiable. Duplicated logic is a bug — it creates drift, increases
maintenance burden, and undermines the single-source-of-truth principle.

### Required Steps

1. **Search before you write.** Use Grep/Glob to search for existing
   implementations that match the intent of what you are about to create.
   Search by concept (e.g., "retry", "timeout", "base64 decode"), not just
   by the exact name you plan to use.
2. **Check neighboring modules.** Read the module and its siblings. If you are
   adding a helper to `engine/core.rs`, read the other files in `engine/` and
   `stdx/` first.
3. **Check utility crates.** `src/stdx/` contains shared data structures and
   helpers. Confirm your functionality is not already there before creating
   a new one.
4. **If similar logic exists, extend or reuse it.** Do not create a parallel
   implementation. Refactor the existing code to be more general if needed.
5. **If you are unsure, ask.** It is always better to ask "does X already
   exist?" than to introduce a duplicate.

### What Counts as Duplication

- A second function that does the same thing with a different name.
- A method that reimplements logic already available in a trait or utility.
- A new struct that is structurally identical to an existing one.
- Copy-pasted blocks with minor variations (extract a shared helper instead).
- A new constant/sentinel that duplicates an existing one.

### Enforcement

If during review a duplicate is found that could have been caught by searching
the codebase first, the change will be rejected. No exceptions.

<!-- end-duplication-prevention -->

## Landing the Plane (Session Completion)

**When ending a work session:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Run `bd sync`** - Persist beads state
5. **Hand off** - Provide context for next session

Do NOT stage, commit, or push code changes. Leave that to the user.
