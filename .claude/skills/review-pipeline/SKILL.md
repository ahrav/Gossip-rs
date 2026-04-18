---
name: review-pipeline
description: Use when you want review AND automated fixes in one pass, when /review-dispatch alone would leave findings unaddressed, or before merging a feature branch that needs thorough diagnosis and remediation. Two-phase diagnose-then-fix pipeline.
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

Launch **two diagnostic agents in parallel** using the Agent tool. Each agent
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

## Synthesis

After both agents complete, merge their findings:

1. **Match by location**: Group findings that reference the same file:line (within 5-line proximity)
2. **Score convergence**: Findings flagged by both agents get a `[CONVERGED]` tag — these are highest confidence
3. **Deduplicate**: If both agents describe the same issue at the same location, keep the more detailed description
4. **Rank**: Sort by: Critical > High > Medium > Low, then converged > single-source
5. **Group by file**: Cluster findings by file path for Phase 2 ownership assignment

## Human Gate

Present findings to the user in this format:

```
## Review Pipeline — Phase 1 Complete

Found {N} issues across {M} files.

### Findings (ranked by severity + convergence)

| #  | Sev      | Location              | Issue                          | Source      |
|----|----------|-----------------------|--------------------------------|-------------|
| 1  | Critical | src/engine/core.rs:42 | Unchecked overflow in merge()  | CONVERGED   |
| 2  | High     | src/engine/core.rs:87 | Missing error propagation      | Specialist  |
| 3  | High     | src/shard/split.rs:15 | Clone in hot loop              | Confidence  |
| 4  | Medium   | src/engine/core.rs:55 | Dead code in fallback path     | CONVERGED   |

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

After fixing, run:
  cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings

Findings to address:

{list of findings with file:line, issue description, and recommended fix}

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

- If a Phase 1 agent fails or times out, proceed with the other agent's findings
- If a Phase 2 agent cannot fix a finding, report it as `SKIPPED` with reason
- If cargo check fails after Phase 2, report the error and let the user decide

## Related Skills

- `/review-dispatch` — Phase 1 methodology (multi-specialist)
- `/ce:review` — Phase 1 methodology (confidence-gated)
- `/execute-review-findings` — Phase 2 methodology
- `/perf-pipeline` — Performance-focused team pipeline
- `/test-pipeline` — Testing-focused team pipeline

## Known Patterns Injection

Before dispatching Phase 1 agents, read `.claude/review-rules.yaml`. For each
rule with `status: active`, inject into both Agent A and Agent B prompts:

> **Known Pattern: {rule.what}** ({rule.category})
> Scope: {rule.scope_dirs} | Why: {rule.why}
> BAD: {rule.bad_example} | GOOD: {rule.good_example}

If the file does not exist or has no active rules, skip this.

## Findings Log

After the synthesis phase, append each merged finding to
`.claude/review-findings.jsonl` (one JSON object per line, confidence >= 0.60).
Use the same schema as `/review-dispatch` (see that skill for the full schema).
Set `source` to `"review-pipeline"`.
