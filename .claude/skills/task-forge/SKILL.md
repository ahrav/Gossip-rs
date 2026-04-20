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

**Simplicity principle (MANDATORY):** Enrichment must reduce complexity, never
add it. Every enrichment recommendation is evaluated against the
`/reduce-complexity` framework: essential complexity stays, accidental is
removed. If Agent B (Implementation) recommends a new abstraction, helper, or
module, it must cite ≥2 concrete call sites that justify the shape — otherwise
inline the logic. `/reduce-complexity` is dispatched whenever the task
introduces new abstractions, touches a file that already exceeds complexity
thresholds, or is labeled "refactor" / "simplify".

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

**Module-to-skill fast lookup (first filter):**

| Module/File | Domain skill candidates |
|-------------|----------------------|
| `src/app.rs` | `/performance-analyzer`, `/security-reviewer`, `/interface-design-review` |
| `src/cache.rs` | `/performance-analyzer`, `/security-reviewer`, `/bench-compare` |
| `src/s3_dynamo_cache_handlers.rs` | `/performance-analyzer`, `/security-reviewer` |
| `src/config.rs` | `/interface-design-review`, `/security-reviewer` |
| `src/utils.rs` | `/performance-analyzer`, `/security-reviewer` |
| `src/interceptors/` | `/performance-analyzer`, `/security-reviewer` |
| `src/metrics/` | `/performance-analyzer`, `/interface-design-review` |

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
| `/interface-design-review` | New pub fn/struct/trait (4), in media-cache-contracts/ (5) | 4 |
| `/security-reviewer` | Path in scanner-git/ (4), keywords: parse/buffer/input validation (3), manual `&[u8]` indexing (4) | 4 |
| `/reduce-complexity` | New abstraction/trait/module proposed (5), keywords: refactor/simplify/cleanup/extensible/flexible/configurable (4), file already >300 LOC or function >100 LOC in "Files to Modify" (3), task_type == refactor or label contains "complexity"/"tech-debt" (5) | 4 |

**Budget caps:**

| Level | Max domain skills | Notes |
|-------|------------------|-------|
| SIMPLE | 0 | — |
| STANDARD | 2 | Mutual exclusions: `/performance-analyzer` XOR `/rust-hotspot-finder`; `/causal-profile` XOR `/perf-topdown` |
| COMPLEX | 3 | Same exclusions; `/test-consolidate` XOR `/test-dedup` |

**Safety override:** `/unsafe-review` and `/security-reviewer` bypass budget caps
when signal weight >= 7.

### Implementation Skill Recommendation

After selecting enrichment skills (dispatched NOW), compute a separate set of
**recommended implementation skills** — skills the IMPLEMENTING agent should
invoke when it picks up the task. These are advisory, not dispatched.

**Distinction:** Enrichment skills analyze the task to produce recommendations.
Implementation skills help the agent execute the work correctly. Choosing the
right skills is the difference between decent and great output.

#### Taxonomy — Organized by Implementation Phase

Skills are grouped by WHEN the implementing agent should invoke them.
Within each phase, skills are ordered by domain and natural chain order.

##### Before Starting Implementation

Use these before writing code — they shape the approach.

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/plan-forge` | COMPLEX task, or multiple viable approaches, or ≥7 files affected | Stress-test the implementation plan before coding starts |
| `/deep-research` | Task involves novel algorithms, safety-critical protocols, or designs where getting it wrong is expensive | Evidence-backed design from papers and production systems |
| `/deeper-research` | `/deep-research` insufficient; topic needs adversarial challenge | 6-phase funnel with adversarial review for highest stakes |
| `/design-tournament` | COMPLEX task with ≥3 viable implementation approaches | Competing proposals evaluated by independent agents |

##### During Implementation

**Testing**

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/test-strategy` | Task creates new test files or significantly changes coverage | Choose the right test type (unit/rstest/proptest/fuzz/kani/sim) |
| `/invariant-test-review` | Task adds/modifies state-machine, simulation, or oracle tests | Ensure tests actually prove the claimed invariant, not just pass |
| `/run-fuzz` | Task handles untrusted input, parsers, or data structure serialization | Crash discovery via cargo-fuzz before merging |

**Performance** (chain: find → analyze → benchmark → optimize)

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/rust-hotspot-finder` | Performance optimization without a specific target function | Scan for likely hotspots before profiling — focus effort |
| `/performance-analyzer` | Task modifies HOT-tier code | Static analysis catches allocation violations and hot-path issues early |
| `/bench-compare` | Task touches functions with existing Criterion benchmarks | Validate no >5% median regression against baseline |
| `/perf-regression` | Task modifies hot-path code in coordination or scanner engine | Full benchmark suite before/after regression test |
| `/asm-forge` | Task modifies tight loops or `#[inline(always)]` in HOT-tier | Instruction-level analysis: bounds checks, register spills, codegen |
| `/simd-optimize` | Task touches byte-processing loops or SIMD paths | Platform-specific intrinsics (x86 + ARM NEON/SVE) with validation |
| `/heap-profile` | Task changes allocation patterns in HOT/WARM tier | Attribute allocations to call sites when AllocGuard trips |
| `/perf-topdown` | Task needs CPU µarch analysis (branch mispredict, cache miss) | Classify slow code: front-end vs back-end vs speculation |
| `/causal-profile` | Task modifies concurrent/async code on critical path | Distinguish critical-path bottlenecks from parallel slack |
| `/linux-perf-profile` | Task needs hardware PMU counters beyond flamegraphs | Source-level drill-down on Linux/ARM/Graviton targets |
| `/perf-pipeline` | Multiple perf dimensions need simultaneous triage | Orchestrates diagnosis + optimization dispatch in one pass |
| `/pgo-bolt` | Final optimization pass on a binary target | 10-30% from I-cache, branch prediction, function layout |

**Safety & Security** (chain: review → wrap → audit)

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/unsafe-review` | Task adds or modifies unsafe blocks | Audit safety invariants; demand benchmark+ASM proof of perf benefit |
| `/safe-over-unsafe` | Task creates pub API wrapping unsafe internals | Design safe wrapper that's hard to misuse |
| `/security-reviewer` | Task handles untrusted input, parsing, or buffer manipulation | Memory safety and security audit |

**Coordination & Distributed Systems** (chain: audit → specify → simulate → test)

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/dist-sys-auditor` | Task modifies coordination protocols or distributed state | Audit against academic literature and battle-tested systems |
| `/tla-spec` | Task changes coordination protocol semantics (leases, epochs, fences) | Formally verify safety/liveness properties before coding |

**Design & Architecture**

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/interface-design-review` | Task adds new pub trait/struct/fn to contracts crate | Misuse-resistant API design review |

**Domain-Specific**

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/rule-optimize` | Task adds/modifies rules in `default_rules.yaml` | Benchmark rule perf against test corpuses; validate anchors |
| `/sqlite-review` | Task touches SQLite schemas, queries, or WAL config | EXPLAIN QUERY PLAN evidence for schema decisions |
| `/postgres-review` | Task touches PostgreSQL schemas or migrations | Lock safety, query performance, and index optimization |

##### After Implementation

**Documentation** (chain: write → verify → audit)

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/doc-rigor` | Always — run after implementation | Write-then-verify documentation pipeline |
| `/doc-rigor-verify` | Task changes pub API signatures, command examples, or platform-specific behavior | Independent accuracy verification with zero confirmation bias |
| `/doc-verify` | Task adds unsafe invariants or changes pub API contracts | Fresh-agent verification against code reality |
| `/doc-code-audit` | Task touches code in scope of a design doc (`project documentation`) | Verify design doc still matches code |
| `/design-doc-audit` | Task touches multiple files covered by design docs, or adds new source files | Comprehensive doc coverage and accuracy check |

**Testing Verification**

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/test-pipeline` | Feature implementation complete; need coverage gap assessment | Two-phase assess-then-improve testing |
| `/test-dedup` | Task added many tests to modules with existing property/sim coverage | Remove redundant unit tests that duplicate higher-level coverage |
| `/test-consolidate` | Task touches test modules with >15 existing similar tests | Consolidate verbose suites into rstest/proptest/fuzz |

**Code Quality**

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/simplify` | Always — run before closing task | Final code simplification pass |
| `/dedup-audit` | Task introduces new types/functions that cross ≥2 crates | Catch accidental duplication before it drifts |

**Review**

| Skill | Recommend When | Why |
|-------|---------------|-----|
| `/review-dispatch` | Task is COMPLEX or crosses ≥3 modules | Six parallel specialist agents for thorough review |
| `/review-pipeline` | COMPLEX task needing review + automated fixes in one pass | Diagnose-then-fix pipeline |
| `/execute-review-findings` | After `/review-dispatch` produces multiple findings | Systematically address findings across files and severities |

#### Skill Chains

When recommending multiple skills from the same domain, ORDER them as chains.
Earlier skills produce findings that inform later skills. The synthesizer
should present chains as ordered sequences, not unordered lists.

| Chain | Progression | Trigger |
|-------|-------------|---------|
| **Perf optimization** | `/rust-hotspot-finder` → `/performance-analyzer` → `/bench-compare` → `/asm-forge` → `/simd-optimize` | HOT-tier optimization task |
| **Perf diagnosis** | `/perf-regression` → `/perf-topdown` → `/causal-profile` → `/linux-perf-profile` | Benchmark regression needing root cause |
| **Coordination** | `/dist-sys-auditor` → `/tla-spec` → `/sim-run` → `/jepsen-test` | Protocol correctness task |
| **Safety** | `/unsafe-review` → `/safe-over-unsafe` → `/security-reviewer` | New or modified unsafe code |
| **Documentation** | `/doc-rigor` → `/doc-verify` → `/design-doc-audit` | Post-implementation doc pass |
| **Testing** | `/test-strategy` → `/invariant-test-review` → `/test-pipeline` → `/test-dedup` | Comprehensive test coverage |
| **Review** | `/review-dispatch` → `/execute-review-findings` → `/simplify` | Pre-merge quality pass |
| **Planning** | `/deep-research` → `/plan-forge` → `/design-tournament` | COMPLEX task kickoff |

**Chain rules:**
- Never recommend a later chain step without also recommending earlier steps.
- If only part of a chain applies, truncate — don't skip middle steps.
- Chains are advisory ordering; the agent may interleave with coding.

#### Selection Process

1. Apply the same signal extraction from the task description.
2. Score each implementation skill against the taxonomy triggers.
3. All matching skills are included — no budget cap (advisory only).
4. Assemble matching skills into chains where applicable. If a skill
   appears in a chain, include preceding chain steps that also match.
5. Each enrichment agent also contributes 0-3 domain-specific picks (Phase 2).
6. The synthesizer (Phase 3) merges, deduplicates, orders by chain,
   and adds concrete invocation context.

#### Invocation Guidance Format

Each recommended skill gets a **when** (at what point during implementation)
and a **why** (what it catches or validates):

```
| Phase | Skill | When to Invoke | Why |
|-------|-------|---------------|-----|
| During | `/bench-compare` | After implementing the optimization | Validate no >5% regression |
| After | `/invariant-test-review` | After writing sim tests | Ensure tests prove claimed invariant |
| After | `/doc-rigor` | After all code is written | Write-then-verify documentation |
```

The orchestrator passes the initial skill set + chain analysis to the synthesizer.

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
| Simulation | Integration tests | Coordination protocol invariants S1-S9, fault tolerance |
| Simulation | Unit tests | Scanner engine detection pipeline |
| Simulation | Integration tests | Scheduler work-stealing, chunking |

## Decision Framework

- Fixed known inputs -> unit test (#[test])
- Finite (input, expected) pairs -> rstest parameterized
- Large/infinite input space -> proptest
- Untrusted/adversarial input -> fuzz test
- Memory safety in unsafe -> Kani proof
- Cache behavior change -> Integration tests
- Proxy behavior change -> Integration tests
- Config change -> Unit tests

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

### Recommended Skills for Implementing Agent
List 0-5 skills from your testing domain that the implementing agent should
invoke. Only recommend if directly relevant. Consider the full palette:
`/sim-run`, `/run-fuzz`, `/jepsen-test`, `/test-pipeline`, `/test-dedup`,
`/test-consolidate`. Order as a chain if multiple apply.
| Skill | When to Invoke | Why |
```

### Agent B — Implementation Enrichment

**Specialty: IMPLEMENTATION APPROACH OPTIMIZATION (simplicity-first)**

Agent B embeds the `/reduce-complexity` framework directly: every
recommendation must be evaluated against essential-vs-accidental complexity,
reuse-over-create, and the anti-abstraction brake.

```
## Your Steps

0. **Simplicity gate (RUN FIRST)**: Before evaluating performance or structure,
   ask: can this task be done with LESS code rather than more?
   - Can any existing function be called with different args instead of a new helper?
   - Can the change be expressed as a 1-line edit rather than a new module?
   - Is the task proposing a new abstraction? If yes, grep for current call
     sites that would use it. Require ≥2; otherwise recommend INLINE.
   - Apply /reduce-complexity thresholds to any new function sketch:
     • LOC projected > 100 → break up or delete scope
     • nesting > 4 → use guard clauses / let-else / early returns
     • params >= 6 → struct the args OR split the function's two concerns
   - Apply the over-abstraction brake:
     `param_count + return_type_fields >= body_lines / 3` → warn
     single call site + >3 params → warn

1. **Classify allocation tier**: For each file in "Files to Modify":
   - HOT: inside engine/core.rs, coordination acquire/complete/checkpoint
     loops, per-claim/per-shard/per-tick iteration, benchmarked functions
   - WARM: query/list/admin operations, not in inner loops
   - COLD: startup, registration, setup/teardown, test helpers
   - Check existing patterns in the file (ByteSlab, InlineVec, with_capacity)

2. **Evaluate proposed approach**: For the task's "Desired State":
   - Is it the simplest correct approach for the allocation tier?
   - Better algorithm? (linear scan vs binary search vs hash, given data size)
   - Better data structure? (Vec vs InlineVec for small collections,
     HashMap vs BTreeMap for ordered access)
   - Can src/utils.rs utilities be reused?
   - **Prefer reuse over create.** If an existing utility is 80% correct,
     extend it; don't clone it.

3. **Check reusable utilities**: Search src/utils.rs for:
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

6. **Simplification opportunities**: For each file in "Files to Modify",
   list accidental complexity the implementing agent should eliminate as part
   of this change (dead branches, redundant checks, unused fields, unnecessary
   wrappers, duplicated logic with sibling modules). Flag as MUST if the task
   fix is blocked by it, SHOULD otherwise.

## Output Format

### Simplicity Analysis (apply /reduce-complexity framework)
| Proposed element | Current call sites | Verdict | Rationale |
|------------------|-------------------|---------|-----------|
(Verdict: KEEP, INLINE, REUSE-EXISTING, DELETE-SCOPE, PARAMETERIZE-LESS)

### Simplification Opportunities
| File:line/function | Accidental complexity | Fix | Priority |

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

### Recommended Skills for Implementing Agent
List 0-5 skills from your performance/implementation domain that the
implementing agent should invoke. Only recommend if directly relevant.
Consider the full palette:
`/performance-analyzer`, `/rust-hotspot-finder`, `/bench-compare`,
`/perf-regression`, `/asm-forge`, `/simd-optimize`, `/heap-profile`,
`/perf-topdown`, `/causal-profile`, `/linux-perf-profile`, `/perf-pipeline`,
`/pgo-bolt`, `/dedup-audit`, `/plan-forge`. Order as a chain if multiple apply.
| Skill | When to Invoke | Why |
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

### Recommended Skills for Implementing Agent
List 0-5 skills from your documentation/quality domain that the implementing
agent should invoke. Only recommend if directly relevant. Consider the full
palette: `/doc-rigor`, `/doc-rigor-verify`, `/doc-verify`, `/doc-code-audit`,
`/design-doc-audit`, `/simplify`, `/dedup-audit`, `/review-dispatch`,
`/review-pipeline`, `/execute-review-findings`.
Order as a chain if multiple apply.
| Skill | When to Invoke | Why |
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
3. **Simplicity wins over ergonomic sugar.** When agents disagree on an
   abstraction, prefer the approach with fewer moving parts, fewer call sites,
   and less indirection — per the `/reduce-complexity` framework.
4. Implementation agent wins on HOT-path constraints
5. Testing agent wins on coverage decisions (what to test)
6. Documentation agent wins on doc scope (what to document)
7. Higher confidence wins when no domain precedence applies

**Cross-agent simplicity filter:** After resolving conflicts, sweep the final
recommendation set for unjustified complexity:
- Any recommendation that adds a new module/trait/abstraction with <2 current
  call sites → demote to a note, not a requirement.
- Any recommendation to "make it more generic" / "add a knob" without concrete
  need → drop.
- Prefer DELETE and REUSE recommendations over CREATE when semantically
  equivalent.

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

### 5. Produce Recommended Skills Section

Merge implementation skill recommendations from three sources:
1. **Orchestrator's taxonomy-based picks** (passed in with this prompt)
2. **Each enrichment agent's "Recommended Skills" output** (0-3 each)
3. **Your own judgment** from reviewing the enrichment findings

For each recommended skill, produce:
- **Skill name** (slash command)
- **When to invoke** (at what point during implementation)
- **Why** (what it catches, validates, or improves — grounded in enrichment findings)

**Ordering:** Skills the agent should invoke DURING implementation first
implementation (e.g., `/bench-compare`, `/doc-rigor`, `/review-dispatch`).

**Deduplication:** If multiple agents recommend the same skill, keep the
most specific "when" and "why". Merge, don't list twice.

**Minimum set:** Always include `/doc-rigor` (after implementation),
`/reduce-complexity` (after implementation, before closing — verify no new
HIGH/CRITICAL hotspots were introduced on modified files), and `/simplify`
(before closing). Omit only if task is TRIVIAL.

### 6. Rate Enrichment Quality

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

### Recommended Skills
Invoke these skills during and after implementation for best results.

| Skill | When to Invoke | Why |
|-------|---------------|-----|
| `/skill-name` | {during/after implementation — specific trigger} | {what it catches or validates} |

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

### Recommended Skills (new)
  - During: {list of skills to invoke during implementation}
  - After:  {list of skills to invoke after implementation}

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
   - **Recommended Skills**: Insert after "Acceptance Criteria", before "Pointers"
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
  Recommended Skills   — {N} skills ({M} during, {K} after)

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
                                  +-- recommends: implementation skills for the picking-up agent
                                  +-- optionally invokes: /review-task (validation)
```

Enrichment agents embed skill methodologies directly in their prompts
(same pattern as `/review-pipeline` embedding `/review-dispatch` in Agent A).
Domain skills are dispatched as parallel agents using the scoped prompt from
`/review-task` Phase 1.5.
