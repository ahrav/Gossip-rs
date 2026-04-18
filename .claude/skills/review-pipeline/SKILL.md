---
name: review-pipeline
description: Use when you want review AND automated fixes in one pass, when /review-dispatch alone would leave findings unaddressed, or before merging a feature branch that needs thorough diagnosis and remediation. Two-phase diagnose-then-fix pipeline with three parallel diagnostic perspectives (multi-specialist, confidence-gated, and complexity-hotspot).
user-invocable: true
---

# Review Pipeline

Two-phase review team: diagnose issues from multiple perspectives, then
systematically fix approved findings.

## When to Use

- Before merging a feature branch
- After completing a significant implementation step
- When you want a thorough review AND fixes in one pass
- When `/review-dispatch` or `/ce:review` alone would leave findings unaddressed

## Invocation

```
/review-pipeline [<target>]
```

- No argument: review unstaged changes in the working tree (`git diff`)
- File path or glob: review specific files
- `--staged`: review staged changes (`git diff --cached`)
- `--branch`: review all commits on the current branch vs main

## Phase 1: Parallel Diagnosis

Launch **three diagnostic agents in parallel** using the Agent tool. Each agent
gets a different review methodology to maximize coverage through perspective
diversity.

### Agent A — Multi-Specialist Review

Prompt this agent with the review-dispatch methodology: six focused review
dimensions applied independently, then merged into a ranked report.

**Dimensions to cover:**
1. **Correctness** — Logic errors, edge cases, state management bugs, error propagation failures, intent-vs-implementation mismatches
2. **Design** — SOLID violations, coupling, unclear abstractions, naming that obscures intent, premature generalization
3. **Performance** — Allocation in hot paths, missing `with_capacity`, lock contention, async blocking, cache-hostile patterns
4. **Safety** — Unsafe soundness, input validation at boundaries, error swallowing, resource leaks
5. **Documentation** — Missing doc comments on public APIs, misleading comments, stale docs
6. **Complexity** — Unnecessary indirection, dead code, over-engineering, functions doing too much

**Agent prompt template:**
```
You are a code reviewer analyzing changes for quality issues. Review the
following code changes across six dimensions: correctness, design, performance,
safety, documentation, and complexity.

For each finding, report:
- Severity: Critical | High | Medium | Low
- Dimension: which of the six
- Location: file:line
- Evidence: what you see in the code
- Impact: what could go wrong
- Recommended fix: actionable remediation

Target: {target_description}

{diff or file contents}
```

### Agent B — Confidence-Gated Review

Prompt this agent with the ce:review methodology: tiered persona agents with
confidence scoring, where only findings above a confidence threshold are
reported.

**Agent prompt template:**
```
You are a senior code reviewer performing a confidence-gated review. For each
potential issue you identify, assign a confidence score (0-100) representing
how certain you are this is a real problem, not a false positive.

Only report findings with confidence >= 60.

For each finding, report:
- Confidence: 0-100
- Severity: Critical | High | Medium | Low
- Location: file:line
- Issue: what is wrong
- Why you are confident: evidence from the code
- Recommended fix: actionable remediation

Target: {target_description}

{diff or file contents}
```

### Agent C — Complexity Hotspot Review

Prompt this agent with the `/reduce-complexity` methodology: metric-based
hotspot detection with ESSENTIAL vs ACCIDENTAL classification and technique
recommendations. This agent catches maintainability issues that subjective
reviewers consistently miss — the "this function grew by 40% in this diff
and is now unreadable" findings.

**Agent prompt template:**
```
You are a complexity analyst. Follow the /reduce-complexity methodology
(Phases 1-4) on the changed code.

Phase 1 — Detection. For every function modified in the diff (including
newly added functions), measure:
- LOC (opening `{` to closing `}`, excluding blanks/comment-only lines)
- Max nesting depth (Rust match discount: exhaustive match on ≤6 enum
  variants counts +0; match on runtime values or >6 variants counts +1)
- Parameter count (including &self/&mut self)

Flag a function if ANY threshold triggers:
  LOC:     Advisory 51-100 | Moderate 101-200 | High 201-400 | Critical >400
  Nesting: Advisory 4      | Moderate 5-6     | High 7+
  Params:  Advisory 6-7    | Moderate 8+

For files with a prior version (git show HEAD:<path> or merge-base), compare
before/after. Prioritize:
  - Functions that newly crossed a threshold boundary
  - Functions whose LOC grew by ≥30%
  - Newly-added functions at Moderate+ severity

Phase 2 — Classification. ESSENTIAL / ACCIDENTAL / MIXED. Tests:
  1. Domain necessity — would a clean-room reimpl have similar structure?
  2. Error-handling — does each branch have distinct recovery?
  3. Sequential coupling — do steps have data dependencies?
  4. Accidental indicators — duplicated blocks, flattenable nesting,
     always-together params, deep nesting wrapping short bodies.

Phase 3 — Suggestions. AT MOST 3 techniques per function from:
  auto-apply: guard clauses, redundant else, remove unnecessary Result,
              type aliases
  suggest:    pass by reference, ? operator, merge match arms, let-else
  flag-for-review: extract function, collapse if-chains, polymorphism,
                   decompose state machine

Phase 4 — Safety. Apply:
  - Unsafe exclusion zone: if the function contains unsafe or is near unsafe
    invariant code, SKIP extract-function suggestions
  - Over-abstraction brake: for extract-function, if
    (param_count + return_fields) >= body_lines / 3, flag for review only
  - Async boundary: extract that crosses .await may break Send bounds
  - Clippy annotation respect: if #[allow(clippy::...)] is present, lower
    confidence one level

For each finding, report:
- Severity: Critical | High | Medium | Low (map from the threshold matrix)
- Dimension: complexity
- Location: file:line
- Classification: ESSENTIAL | ACCIDENTAL | MIXED
- Metrics: LOC / nesting / params (and before-state if changed)
- Evidence: what is driving the complexity
- Recommended fix: AT MOST 3 ranked techniques with safety warnings

Suppress findings classified ESSENTIAL — report them in a short "Essential
complexity (leave alone)" appendix so Synthesis can ignore them for merge
but surface them in the Human Gate summary.

Target: {target_description}

{diff or file contents}
```

## Synthesis

After all three agents complete, merge their findings:

1. **Match by location**: Group findings that reference the same file:line (within 5-line proximity)
2. **Score convergence**: Findings flagged by 2+ agents get a `[CONVERGED:N]` tag (where N is the agent count) — these are highest confidence
3. **Deduplicate**: If multiple agents describe the same issue at the same location, keep the most detailed description. For complexity findings from Agent C that converge with design findings from Agent A, prefer Agent C's classification (ESSENTIAL / ACCIDENTAL / MIXED) and technique list — it carries the safety checks
4. **Drop ESSENTIAL-only findings**: Agent C findings classified ESSENTIAL with no converging Agent A or B finding are moved to an "Essential complexity (informational)" appendix and NOT surfaced in the approval table. Pure metric-based complaints about inherent domain complexity should not gate merges
5. **Rank**: Sort by: Critical > High > Medium > Low, then CONVERGED:3 > CONVERGED:2 > single-source
6. **Group by file**: Cluster findings by file path for Phase 2 ownership assignment

## Human Gate

Present findings to the user in this format:

```
## Review Pipeline — Phase 1 Complete

Found {N} issues across {M} files.

### Findings (ranked by severity + convergence)

| #  | Sev      | Location              | Issue                                       | Source        |
|----|----------|-----------------------|---------------------------------------------|---------------|
| 1  | Critical | src/engine/core.rs:42 | Unchecked overflow in merge()               | CONVERGED:3   |
| 2  | High     | src/engine/core.rs:87 | Missing error propagation                   | Specialist    |
| 3  | High     | src/shard/split.rs:15 | Clone in hot loop                           | Confidence    |
| 4  | High     | src/engine/core.rs:120 | merge_all() grew 85→240 LOC [ACCIDENTAL]   | Complexity    |
| 5  | Medium   | src/engine/core.rs:55 | Dead code in fallback path                  | CONVERGED:2   |
| 6  | Medium   | src/shard/split.rs:88 | Nesting depth 7 in split_shard [ACCIDENTAL] | Complexity    |

### Essential complexity (informational — no action recommended)

| Location              | Why Essential                                             |
|-----------------------|-----------------------------------------------------------|
| src/engine/recover.rs | 6-stage state machine; stages share error-recovery narrative |

Approve all? Or enter finding numbers to address (e.g., "1,2,3"):
```

Wait for user response. Accept:
- "all" or empty → approve all findings
- Comma-separated numbers → approve only those findings
- "none" or "skip" → skip Phase 2 entirely

## Phase 2: Targeted Execution

For each approved finding, dispatch execution agents to apply fixes.

### File Ownership

Group approved findings by file. Each execution agent owns a non-overlapping
set of files. If multiple findings target the same file, they go to the same
agent.

### Agent Dispatch

For each file group, launch an Agent with this prompt:

```
You are fixing code review findings. Apply the minimum change needed to
address each finding correctly. Do not refactor beyond what the finding
requires.

For any finding with Dimension=complexity OR classification ACCIDENTAL/MIXED,
follow the /reduce-complexity methodology:
  1. Apply AT MOST 3 techniques per function. More than that signals broader
     redesign is needed — stop and report back, do not proceed.
  2. Respect the safety checks before editing:
     - Unsafe exclusion zone: if the function contains `unsafe` or calls
       unsafe helpers nearby, SKIP extract-function. Only guard clauses and
       redundant-else removal are allowed.
     - Over-abstraction brake: for extract-function, compute
       (param_count + return_fields) / body_lines. If ≥ 0.33, report the
       check failure and skip the extraction.
     - Async boundary: if extracting code that crosses `.await`, run
       `cargo check` immediately after the extraction — Send bounds on
       captured types often fail silently at the file level.
     - Clippy annotation respect: if the function has `#[allow(clippy::...)]`,
       the original author made a deliberate decision — do not overrule it.
  3. If the finding conflicts with an ESSENTIAL classification elsewhere in
     the same function, STOP. Report the conflict instead of refactoring.

After fixing, run:
  cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings

Findings to address:

{list of findings with file:line, issue description, classification, and
 recommended fix}

Files you own (only modify these):
{list of files in this group}
```

### Parallel vs Sequential

- File groups with no overlap → dispatch agents **in parallel**
- If a finding spans multiple files that overlap with another group → run **sequentially**

### Completion

After all execution agents finish, present a summary:

```
## Review Pipeline — Complete

### Changes Applied

| Finding | Status  | Files Modified              |
|---------|---------|-----------------------------|
| #1      | Fixed   | src/engine/core.rs          |
| #2      | Fixed   | src/engine/core.rs          |
| #3      | Fixed   | src/shard/split.rs          |

### Verification

Run to confirm:
  cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all-features
```

## Error Handling

- If one Phase 1 agent fails or times out, proceed with the other two — do not block on a single agent. Note the missing perspective in the Human Gate output so the user can re-run if desired
- If two Phase 1 agents fail, abort Phase 1 and report; a single agent's findings are not diverse enough to justify auto-fixes
- If a Phase 2 agent cannot fix a finding, report it as `SKIPPED` with reason
- If cargo check fails after Phase 2, report the error and let the user decide

## Related Skills

- `/review-dispatch` — Phase 1 methodology for Agent A (multi-specialist)
- `/ce:review` — Phase 1 methodology for Agent B (confidence-gated)
- `/reduce-complexity` — Phase 1 methodology for Agent C (complexity hotspots with ESSENTIAL/ACCIDENTAL classification); also gates Phase 2 refactoring safety
- `/execute-review-findings` — Phase 2 methodology
- `/perf-pipeline` — Performance-focused team pipeline
- `/test-pipeline` — Testing-focused team pipeline
