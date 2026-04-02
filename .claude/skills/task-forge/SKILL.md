---
name: task-forge
description: Use when creating implementation-ready beads tasks that need testing strategy, optimal implementation approach, and documentation requirements baked in — composes /create-task with parallel enrichment agents that analyze the codebase and produce concrete test specifications, algorithm/data-structure guidance, and doc quality standards so implementing agents don't need to re-research
user-invocable: true
---

# Task Forge

Multi-agent pipeline: create a beads task, then enrich it with concrete testing,
implementation, and documentation guidance so the implementing agent knows exactly
what to build.

**Core principle:** Invest enrichment effort at creation time to eliminate rework
at implementation time.

## When to Use

- Creating any non-trivial beads task (features, bugs touching multiple files,
  coordination changes, performance-sensitive code)
- Enriching an existing task that lacks testing strategy or implementation depth
- When `/create-task` alone would produce a task needing significant follow-up research

**When NOT to use:**
- Trivial tasks (rename, typo, constant addition) — use `/create-task` directly
- When you only need validation — use `/review-task` instead

## Invocation

```
/task-forge "Fix off-by-one in window boundary check" --type=bug --priority=1
/task-forge --task=<existing-id>
/task-forge --dry-run "Refactor transform chain"
/task-forge --skip-enrichment "Add capacity hint" --type=task --priority=3
```

| Flag | Effect |
|------|--------|
| `--task=<id>` | Enrich an existing task instead of creating a new one |
| `--dry-run` | Print enriched task without creating/updating in beads |
| `--skip-enrichment` | Create via `/create-task` only, no enrichment |
| `--type`, `--priority`, `--labels`, `--files-hint`, `--parent`, `--quick` | Passed through to `/create-task` |

---

## Pipeline Overview

```
Phase 0  Create task (/create-task or load existing)
   |
Phase 1  Classify complexity + select domain skills (orchestrator, inline)
   |     Short-circuit: TRIVIAL -> output unchanged
   |
Phase 2  Parallel enrichment (3 agents + 0-2 domain skills)
   |     Agent A: Testing | Agent B: Implementation | Agent C: Documentation
   |     + domain skills dispatched based on signal scoring
   |
Phase 3  Synthesis (1 agent)
   |     Merge findings, resolve conflicts, filter by priority
   |
Gate     User approves / modifies / skips enrichments
   |
Phase 4  Integrate enrichments into task description
   |
Phase 5  Output summary
```

**Agent count:** 4-6 for standard/complex tasks. 0 for trivial.

---

## Phase 0 — Input & Task Creation

**New task** (default): Invoke `/create-task` with all provided arguments.
Capture the task ID and full description.

**Existing task** (`--task=<id>`): Run `bd show <id>`. If description < 5 lines,
warn and recommend `/create-task` first. Stop.

---

## Phase 1 — Classify & Select Skills

The orchestrator performs classification inline (no sub-agent).

### Signal Extraction

Extract from the task description:

| Signal | Source |
|--------|--------|
| `files_affected` | Count rows in "Files to Modify" table |
| `modules_crossed` | Count distinct crate directories in file paths |
| `touches_hot_path` | File path in engine/, coordination/ inner loops, stdx/ |
| `has_unsafe` | `unsafe` in code snippets or referenced files |
| `task_type` | Metadata: bug, task, feature, epic |
| `priority` | Metadata: 0-4 |
| `description_length` | Line count |

### Classification

```
TRIVIAL (all must hold):
  files_affected <= 1, modules_crossed <= 1,
  NOT touches_hot_path, NOT has_unsafe,
  task_type NOT IN (epic, feature), description_length >= 30
  -> Skip enrichment. Output task unchanged.

SIMPLE:
  files_affected <= 3, modules_crossed <= 1, priority >= 2
  -> Lightweight enrichment: Testing Agent + Doc Agent only.

COMPLEX (any triggers):
  files_affected >= 7, OR modules_crossed >= 3,
  OR task_type == epic,
  OR (priority <= 1 AND (touches_hot_path OR has_unsafe))
  -> Full enrichment + up to 3 domain skills.

STANDARD (default):
  Everything else.
  -> Full enrichment (3 agents) + up to 2 domain skills.
```

Present classification to user with override option (`enrich`, `skip`, `complex`).

### Domain Skill Selection — Signal Scoring

For STANDARD/COMPLEX tasks, select domain skills using weighted signals.
Dispatch when total weight >= threshold.

**Crate-to-skill fast lookup (first filter):**

| Crate | Domain skill candidates |
|-------|----------------------|
| `gossip-coordination` | `/dist-sys-auditor`, `/sim-review`, `/invariant-test-review` |
| `gossip-stdx` | `/unsafe-review` (if unsafe), `/performance-analyzer` |
| `scanner-engine` | `/performance-analyzer`, `/simd-optimize` (if simd files), `/security-reviewer`, `/bench-compare` |
| `scanner-git` | `/security-reviewer`, `/performance-analyzer` |
| `scanner-scheduler` | `/performance-analyzer`, `/sim-review` (if sim paths), `/bench-compare` |
| `gossip-scanner-runtime` | `/dist-sys-auditor`, `/causal-profile` |
| `gossip-connectors` | `/interface-design-review`, `/security-reviewer` |

**Signal tables (second filter):**

| Skill | Trigger signals (weight) | Threshold |
|-------|-------------------------|-----------|
| `/performance-analyzer` | HOT-tier path (5), keywords: allocation/hot path/latency (3), `.clone()` in loop (4) | 5 |
| `/bench-compare` | Crate has `benches/` with Criterion (5), function called from benchmark (4) | 5 |
| `/simd-optimize` | File imports `std::arch` (5), keywords: SIMD/vectorize/NEON/AVX (4) | 5 |
| `/asm-forge` | Keywords: codegen/assembly/inline(always) (4), `#[inline(always)]` in HOT-tier (3) | 4 |
| `/dist-sys-auditor` | Path in coordination/ (5), keywords: lease/epoch/fence/shard (4) | 4 |
| `/sim-review` | Path in sim/ (5), keywords: simulation/deterministic/DST (4) | 4 |
| `/unsafe-review` | File contains `unsafe` (5), keywords: raw pointer/MaybeUninit/transmute (4) | 4 |
| `/safe-over-unsafe` | New `pub` API wrapping unsafe (5). Only if `/unsafe-review` also triggers. | 5 |
| `/interface-design-review` | New pub fn/struct/trait (4), in gossip-contracts/ (5) | 4 |
| `/security-reviewer` | Path in scanner-git/ (4), keywords: parse/buffer/input validation (3), manual `&[u8]` indexing (4) | 4 |

**Budget caps:**

| Level | Max domain skills | Notes |
|-------|------------------|-------|
| SIMPLE | 0 | — |
| STANDARD | 2 | Mutual exclusions: `/performance-analyzer` XOR `/rust-hotspot-finder`; `/causal-profile` XOR `/perf-topdown` |
| COMPLEX | 3 | Same exclusions; `/test-consolidate` XOR `/test-dedup` |

**Safety override:** `/unsafe-review` and `/security-reviewer` bypass budget caps
when signal weight >= 7.

---

## Phase 2 — Parallel Enrichment

Launch **all enrichment agents + domain skills in a single message** using the
Agent tool. Each agent gets the full task description, scope assessment, and
project policies.

### Common Preamble (included in all three agent prompts)

```
You are a task enrichment specialist. Your ONE job: enrich the task below
through the lens of {SPECIALTY}. Do NOT implement the task. Do NOT modify
files. Explore the codebase (Read, Grep, Glob) to ground recommendations.

This project has `colgrep` installed - a semantic code search tool.
Use `colgrep` (via Bash) as your PRIMARY search tool instead of Grep/Glob.
- Semantic search: `colgrep "error handling" -k 10`
- Regex + semantic: `colgrep -e "fn.*test" "unit tests"`

## Task Under Enrichment

{FULL_TASK_DESCRIPTION}

## Scope Assessment

- Complexity: {TRIVIAL|SIMPLE|STANDARD|COMPLEX}
- Files affected: {N} | Modules crossed: {N}
- Touches HOT path: {yes|no} | Has unsafe: {yes|no}
- Task type: {type} | Priority: P{N}

## Project Policies (MUST respect)

- **Allocation tiers**: HOT (per-shard/per-claim loops — allocation-silent),
  WARM (frequent ops — simplicity first), COLD (startup — no constraints)
- **No versioning**: No V1/V2, no deprecated, no compatibility shims
- **Error types**: thiserror + existing macros (impl_from_coord_error!, etc.)
- **Comment policy**: No tracking IDs, PR refs, temporal narration
- **Duplication prevention**: Search before creating anything new

## Output Rules

- Be concrete: cite file paths, function names, code patterns from the codebase.
- Rate each recommendation: MUST | SHOULD | COULD, with confidence 0-100%.
- Discard anything below 50% confidence.
- Maximum 10 recommendations. Focus on highest value.
```

### Agent A — Testing Enrichment

**Specialty: TESTING STRATEGY**

Agent A embeds the `/test-strategy` decision framework directly:

```
## Testing Toolkit

| Type | Tool | Best For |
|------|------|----------|
| Unit | #[test] | Specific behavior, edge cases, regression |
| Parameterized | rstest | Finite (input, expected) pairs, enum mappings |
| Property | proptest | Invariants over input domains, roundtrips |
| Fuzz | cargo-fuzz | Untrusted input, parsers, security-critical |
| Model Check | Kani | Memory safety proofs, absence of panics in unsafe |
| Simulation | CoordinationSim | Coordination protocol invariants S1-S9, fault tolerance |
| Simulation | TigerHarness | Scanner engine detection pipeline |
| Simulation | SchedulerSim | Scheduler work-stealing, chunking |

## Decision Framework

- Fixed known inputs -> unit test (#[test])
- Finite (input, expected) pairs -> rstest parameterized
- Large/infinite input space -> proptest
- Untrusted/adversarial input -> fuzz test
- Memory safety in unsafe -> Kani proof
- Coordination protocol change -> CoordinationSim
- Scanner engine change -> TigerHarness
- Scheduler change -> SchedulerSim

## Your Steps

1. **Audit existing coverage**: For each file in "Files to Modify", find
   #[cfg(test)] mod tests, sibling test files, proptest/rstest usage.
   Catalog what IS tested and what IS NOT tested.

2. **Apply decision framework**: For each untested or new behavior, decide
   the test type using the framework above.

3. **Check duplication risk**: For each recommended test, search existing
   tests that might already cover this behavior. Flag overlap.

4. **Specify concrete tests**: For each recommendation provide:
   - Test name (test_{behavior}_{condition})
   - Test type
   - File location (which mod tests block)
   - Inputs to test
   - Property or invariant being verified
   - 5-10 line Rust code sketch (real code, not pseudocode)
   - Dependencies needed (rstest.workspace = true, feature flags)

5. **Specify what NOT to test**: Behaviors already covered by existing
   proptest/sim tests. This prevents test duplication.

## Dependencies Reference

- rstest: workspace dep "0.25" — add rstest.workspace = true to [dev-dependencies]
- proptest: direct dev-dependency (no feature gate)
- Simulation: feature "test-support" or "scheduler-sim" or "tiger-harness"
- Kani: feature "kani", run with cargo kani
- Fuzz: targets in crates/<crate>/fuzz/fuzz_targets/

## Output Format

### Existing Coverage Audit
| File | Tests Found | Coverage Assessment |

### Recommended Tests
For each:
- **Name**: test_{behavior}_{condition}
- **Type**: {unit|rstest|proptest|fuzz|kani|sim}
- **Location**: {file}:{mod tests}
- **Property**: {what this proves}
- **Priority**: {MUST|SHOULD|COULD} | **Confidence**: {N}%
- **Duplication risk**: {none|low|high — reason}
- **Code sketch**:
(5-10 lines of concrete Rust test code)

### Do NOT Test (Already Covered)
| Behavior | Covered By | Location |

### Test Dependencies
| Dependency | Crate | How to Add |
```

### Agent B — Implementation Enrichment

**Specialty: IMPLEMENTATION APPROACH OPTIMIZATION**

```
## Your Steps

1. **Classify allocation tier**: For each file in "Files to Modify":
   - HOT: inside engine/core.rs, coordination acquire/complete/checkpoint
     loops, per-claim/per-shard/per-tick iteration, benchmarked functions
   - WARM: query/list/admin operations, not in inner loops
   - COLD: startup, registration, setup/teardown, test helpers
   - Check existing patterns in the file (ByteSlab, InlineVec, with_capacity)

2. **Evaluate proposed approach**: For the task's "Desired State":
   - Is it the most efficient for the allocation tier?
   - Better algorithm? (linear scan vs binary search vs hash, given data size)
   - Better data structure? (Vec vs InlineVec for small collections,
     HashMap vs BTreeMap for ordered access)
   - Can gossip-stdx utilities be reused?

3. **Check reusable utilities**: Search crates/gossip-stdx/src/ for:
   - ByteSlab/ByteSlot — byte pooling
   - InlineVec<T, N> — stack-first small collections
   - RingBuffer<T, N> — fixed-capacity circular queue
   - AcquireScratch/FixedBuf — reusable scratch buffers
   Search sibling modules for existing patterns.

4. **Identify performance constraints**:
   - HOT: allocation points to avoid, branchless opportunities,
     SIMD-amenable patterns, false sharing risks
   - WARM: unnecessary allocations, with_capacity opportunities
   - COLD: no constraints, optimize for clarity

5. **Find existing patterns**: Has this algorithm been implemented elsewhere?
   What error handling and return types do sibling functions use?

## Output Format

### Allocation Tier Classification
| File | Tier | Evidence | Constraints |

### Algorithm & Data Structure Recommendations
For each:
- **Location**: {file:line or function}
- **Current approach**: {what task says or implies}
- **Recommended approach**: {better alternative}
- **Why**: {complexity, allocation, benchmark evidence}
- **Priority**: {MUST|SHOULD|COULD} | **Confidence**: {N}%
- **Code sketch**: (concrete Rust code if non-obvious)

### Reusable Utilities
| Utility | Location | How to Apply |

### Performance Constraints (for implementing agent)
- {constraint with rationale}

### Anti-Patterns to Avoid
| Anti-Pattern | Why | What to Do Instead |
```

### Agent C — Documentation Enrichment

**Specialty: DOCUMENTATION REQUIREMENTS**

```
## Your Steps

1. **Audit doc state**: For each file in "Files to Modify":
   - Module-level docs present? Accurate?
   - Type docs on pub structs/enums/traits?
   - Function docs on pub fn with params/returns/errors/panics?
   - # Safety sections on unsafe functions?
   - # Examples on public APIs with non-obvious usage?
   - Stale docs that no longer match current code?

2. **Determine requirements based on task changes**:
   - New pub types -> type-level docs (purpose, invariants)
   - New pub functions -> function docs (params, returns, errors, panics)
   - New unsafe -> # Safety section with invariants
   - New algorithms -> algorithm overview (complexity, design trade-offs)
   - Changed behavior -> update docs on affected items
   - New error variants -> doc on each variant (when it occurs)

3. **Specify quality standards per item**:
   - [ ] Problem statement and scope
   - [ ] Invariants and safety rules
   - [ ] Algorithm overview (if applicable)
   - [ ] Design trade-offs (if applicable)
   - [ ] Edge cases and failure modes
   - [ ] Complexity/performance constraints (if applicable)
   - [ ] Examples (if public API with non-obvious usage)

4. **Reference existing patterns**: Find well-documented sibling code.
   Cite as "document like {file:line}" with rationale.

## Project Comment Policy (MUST follow)

Comments must stand alone. No tracking IDs, milestone labels, PR references,
temporal narration ("previously", "was changed from"), or conversational tone.
A reader with no access to PR/issue tracker must understand the comment.

## Output Format

### Current Doc Coverage
| File | Module Docs | Type Docs | Function Docs | Gaps |

### Required Documentation
For each:
- **Item**: {type/function/module name}
- **File**: {path}
- **Scope**: {module|type|function|inline}
- **Must cover**: {checklist items that apply}
- **Pattern to follow**: {file:line of similar well-documented item}
- **Priority**: {MUST|SHOULD|COULD} | **Confidence**: {N}%

### Doc Quality Checklist (for implementing agent)
- [ ] {specific item relevant to this task}

### Stale Docs to Update
| File:Line | Current Doc | What Changed | Required Update |
```

### Domain Skill Dispatch

For each domain skill selected in Phase 1, dispatch as a parallel Agent using
the scoped prompt pattern from `/review-task` Phase 1.5:

```
You are being invoked as a domain enrichment step during task forge.
Your job is NOT a full audit. Produce a focused report answering:

- What domain-specific edge cases or gotchas does the task miss?
- What domain-specific patterns, utilities, or conventions should it reference?
- What domain-specific acceptance criteria should be added?
- What domain-specific risks should be called out?

Keep output concise — 5-15 specific, actionable items.

## Task Description
{FULL_TASK_DESCRIPTION}

## Your Domain
{SKILL_NAME}: {brief scope description}
```

If a domain skill fails or times out, proceed without it. Note the gap in
the synthesis.

---

## Phase 3 — Synthesis

After all Phase 2 agents complete, launch **one synthesizer agent**.

### Synthesizer Prompt

```
You are the Task Forge Synthesizer. Three enrichment agents have independently
analyzed a beads task. Your job: merge their outputs into coherent enrichment
sections ready to be integrated into the task description.

## Original Task
{FULL_TASK_DESCRIPTION}

## Enrichment Reports
### Testing Enrichment (Agent A)
{REPORT}

### Implementation Enrichment (Agent B)
{REPORT}

### Documentation Enrichment (Agent C)
{REPORT}

{DOMAIN_ENRICHMENT_REPORTS if any}

## Your Responsibilities

### 1. Resolve Conflicts

Check for contradictions between agents:
- Testing recommends proptest but Implementation says HOT path forbids
  generator allocations -> use Kani proof or inline unit test instead
- Implementation recommends InlineVec but Testing sketch uses Vec
  -> update sketch to match implementation
- Doc agent says add # Examples but Implementation says API is internal
  -> skip examples, add inline comments instead

**Conflict resolution precedence:**
1. Project policy always wins (allocation tiers, comment policy, no-versioning)
2. Correctness/safety always wins over performance/ergonomics
3. Implementation agent wins on HOT-path constraints
4. Testing agent wins on coverage decisions (what to test)
5. Documentation agent wins on doc scope (what to document)
6. Higher confidence wins when no domain precedence applies

### 2. Deduplicate

Merge overlapping recommendations from multiple agents.

### 3. Filter

- Keep all MUST items.
- Keep SHOULD with confidence >= 60%.
- Discard COULD with confidence < 70%.

### 4. Produce Integrated Enrichment Sections

Structure output as sections ready for task insertion:

#### Testing Strategy
(Replaces any existing section. Include concrete test names, types,
code sketches, and what NOT to test.)

#### Implementation Guidance Addendum
(Appended to existing Implementation Guidance. Algorithm/data structure
recommendations, allocation constraints, reusable utilities, anti-patterns.
Do NOT duplicate what's already in the task.)

#### Documentation Requirements
(New section. What docs to write, quality standards, patterns to follow.)

#### Performance Considerations
(New or replacement section, if applicable. Merge implementation agent's
allocation tier analysis with domain skill performance findings.)

### 5. Rate Enrichment Quality

- STRONG: All three areas enriched with high-confidence recommendations.
  Task is implementation-ready.
- ADEQUATE: Most areas enriched. Some gaps due to low confidence.
  Task is implementable with minor research.
- WEAK: Significant gaps remain. Recommend running specific skills
  separately for deeper analysis.

## Output Format

## Task Forge Synthesis

**Quality**: {STRONG|ADEQUATE|WEAK}
**Conflicts resolved**: {N}
**Recommendations kept**: {N} of {total}
**Domain skills included**: {list or "none"}

### Conflicts Resolved
| # | Conflict | Resolution | Precedence Rule |

### Testing Strategy
{complete section content}

### Implementation Guidance Addendum
{content to append}

### Documentation Requirements
{complete section content}

### Performance Considerations
{content, if applicable}

### Filtered Out
| # | Agent | Recommendation | Reason Dropped |
```

---

## Human Gate

Present synthesis summary to user:

```
## Task Forge — Enrichment Complete

Task: {id} — {title}
Complexity: {level} | Quality: {STRONG|ADEQUATE|WEAK}
Agents: Testing, Implementation, Documentation
Domain skills: {list or "none"} | Conflicts resolved: {N}

### Testing Strategy (new)
  - N unit, N property, N parameterized (rstest), N other (fuzz/kani/sim)

### Implementation Guidance (additions)
  - Allocation tier: {HOT|WARM|COLD}
  - Key constraints: {list}

### Documentation Requirements (new)
  - N type docs, N function docs, N module docs

Options:
  - "approve" — apply all enrichments
  - "approve testing,implementation" — apply specific sections only
  - "edit" — show full enrichment text for manual editing
  - "skip" — discard enrichments, keep original task
  - "review" — also run /review-task on the enriched task
```

---

## Phase 4 — Integration

After user approval:

1. Read current task: `bd show <task-id>`
2. Merge enrichment sections into description:
   - **Testing Strategy**: Insert after "Code References" section
   - **Implementation Guidance Addendum**: Append to existing "Implementation Guidance"
   - **Documentation Requirements**: Insert after "Testing Strategy"
   - **Performance Considerations**: Replace or insert after "Documentation Requirements"
3. Remove addressed `[NEEDS ENRICHMENT]` markers
4. Update: `bd update <task-id> --description="$ENRICHED_DESC"`
5. Add metadata footer: `<!-- task-forge: skills=[...] date=YYYY-MM-DD -->`
6. If user chose "review": invoke `/review-task <task-id>`

### Validation Before Updating

- No enrichment section contradicts "Desired State"
- All file paths in enrichment sections exist in the codebase
- No banned comment patterns in enrichment text
- Test code sketches reference correct types and imports

---

## Phase 5 — Output

```
Task: {id} — {title}
Status: Enriched | Quality: {STRONG|ADEQUATE|WEAK}

Sections Added/Updated:
  Testing Strategy     — {N} tests specified
  Implementation       — {N} recommendations
  Documentation        — {N} doc items
  Performance          — {N} constraints (if applicable)

Next: bd update {id} --status=in_progress
  Or: /review-task {id}
```

---

## Error Handling

| Failure | Behavior |
|---------|----------|
| `/create-task` fails (Phase 0) | Report error, stop. |
| 1 enrichment agent fails (Phase 2) | Proceed with remaining agents. Note gap. |
| 2+ agents fail (Phase 2) | Report failure, offer to run survivors alone or abort. |
| Domain skill fails (Phase 2) | Proceed without it. Record in synthesis. |
| Synthesizer fails (Phase 3) | Present enrichment reports raw. User picks what to apply. |
| `bd update` fails (Phase 4) | Print enriched description for manual application. |

## Idempotency

The metadata footer tracks dispatched skills. On re-invocation, skip
already-dispatched skills unless task description changed (hash comparison).

## Relationship to Existing Skills

```
/task-forge = /create-task + classification + enrichment + synthesis
                                  |
                                  +-- embeds: /test-strategy methodology
                                  +-- embeds: /doc-rigor methodology
                                  +-- dispatches: domain skills (perf, dist-sys, unsafe, etc.)
                                  +-- optionally invokes: /review-task (validation)
```

Enrichment agents embed skill methodologies directly in their prompts
(same pattern as `/review-pipeline` embedding `/review-dispatch` in Agent A).
Domain skills are dispatched as parallel agents using the scoped prompt from
`/review-task` Phase 1.5.
