---
name: execute-review-findings
description: Use when you have code review findings, PR comments, or review reports that need to be systematically addressed — especially when there are multiple findings across different files and severities
---

# Execute Review Findings

Systematically convert review findings into tracked tasks and execute them in priority waves with parallel agents where files don't overlap.

**Core principle:** Normalize findings → create self-contained beads tasks → analyze concurrency → execute in priority waves with parallel dispatch.

## When to Use

- After `/review-dispatch` produces a ranked findings report
- After receiving multiple PR review comments
- When handed an ad-hoc review document (security audit, perf report, etc.)
- When a review produced 3+ findings that span multiple files

## When NOT to Use

- Single finding — just fix it directly
- Findings are all in the same function — no parallelism benefit
- You haven't read the code yet — understand first, then act

## Invocation

```
/execute-review-findings <source>
```

**Source options:**
- `pr` or `pr:<number>` — fetch PR comments via `gh api`
- `review` — use the most recent `/review-dispatch` output in conversation
- `<file-path>` — read a markdown review document from disk
- *(no argument)* — prompt user to paste or describe findings

## Phase 1: Gather & Normalize

Parse findings from any source into a uniform list. Each normalized finding has:

| Field | Description |
|-------|-------------|
| `id` | Sequential number (F1, F2, ...) |
| `severity` | MUST FIX / SHOULD FIX / CONSIDER / NIT |
| `type` | bug, performance, safety, documentation, design, complexity |
| `file` | File path(s) affected |
| `line` | Line number(s) or range |
| `summary` | One-line description |
| `detail` | Full finding with current → desired behavior |
| `specialists` | Which reviewers flagged it (if from `/review-dispatch`) |

**Parsing rules by source:**

- **`/review-dispatch` output**: Parse the ranked tables directly. Map importance 9-10 → MUST FIX, 7-8 → SHOULD FIX, 5-6 → CONSIDER, 1-4 → NIT.
- **PR comments**: Fetch via `gh api repos/{owner}/{repo}/pulls/{number}/comments`. Categorize each: bug claim → bug type, style suggestion → design/complexity, question → skip (reply only).
- **Markdown document**: Look for severity markers, tables, or heading-based grouping. Map to standard severities.

Present the normalized table to the user for confirmation before proceeding.

## Phase 2: Create Beads Tasks

Create one `bd create` per finding. Each task description must be **fully self-contained** — a fresh agent can work it without reading the original review.

### Task Description Template (All Types)

```
## Finding: {summary}

**Severity**: {severity}
**File(s)**: {file}:{line}
**Type**: {type}
**Flagged by**: {specialists}

### Problem
{detail — full finding including current behavior and why it matters}

### Resolution Steps
{type-specific steps — see below}

### Acceptance Criteria
- [ ] {specific, verifiable conditions}
- [ ] All existing tests pass: `cargo test`
- [ ] Code compiles clean: `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings`
```

### Type-Specific Resolution Steps

**Bug** (TDD mandatory):
```
1. Write a failing test that reproduces the bug
   - Test name: descriptive of the behavior, NOT the review
   - Place in the appropriate test module for the file
2. Run test, confirm it FAILS: `cargo test <test_name> -- --nocapture`
3. Fix the production code — minimal change to pass the test
4. Run full suite: `cargo test`
5. Verify clean: `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings`
```

**Performance**:
```
1. Establish baseline: run relevant benchmark or add one if none exists
   - Use `/bench-compare` if Criterion benchmarks cover this path
2. Implement the optimization
3. Re-benchmark and compare against baseline
4. Verify no regressions: `cargo test`
5. Verify clean: `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings`
```

**Safety** (unsafe code):
```
1. Write a test exercising the unsafe path with edge-case inputs
2. Fix the safety issue (bounds checks, invariant enforcement, etc.)
3. Add or update `// SAFETY:` comment documenting invariants
4. Run tests: `cargo test`
5. If Miri-compatible: `cargo +nightly miri test <test_name>`
6. Verify clean: `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings`
```

**Documentation**:
```
1. Read the code the docs describe — understand actual behavior
2. Write or update documentation to match reality
3. Check AGENTS.md consistency table — if touched file is listed, update corresponding docs
4. Verify doc tests compile: `cargo test --doc`
5. Verify clean: `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings`
```

**Design / Complexity**:
```
1. Read surrounding code to understand existing patterns
2. Refactor to address the finding while preserving behavior
3. Run full test suite to confirm no regressions: `cargo test`
4. Verify clean: `cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings`
```

### Priority Mapping for `bd create`

| Severity | bd priority |
|----------|-------------|
| MUST FIX | 1 |
| SHOULD FIX | 2 |
| CONSIDER | 3 |
| NIT | 4 |

### Example

```bash
bd create --title="Fix off-by-one in window boundary check" --type=bug --priority=1
```

Then update the description with the full self-contained template using `bd update <id> --description="..."`.

## Phase 3: Concurrency Analysis

Determine which tasks can run in parallel vs. must run sequentially.

### Step 1: Build File-Touch Map

For each task, list every file it will read or write:

| Task | Writes | Reads |
|------|--------|-------|
| F1 | src/engine/core.rs | src/engine/mod.rs |
| F2 | src/engine/scratch.rs | - |
| F3 | src/engine/core.rs | src/api.rs |

### Step 2: Identify Conflicts

Two tasks conflict if they **write to the same file**. Read-read and read-write of different files are fine.

### Step 3: Form Parallel Groups

Within each severity wave, group non-conflicting tasks:

```
Wave 1 (MUST FIX):
  Group A (parallel): F1, F4  — no file overlap
  Group B (sequential after A): F3  — conflicts with F1 on core.rs

Wave 2 (SHOULD FIX):
  Group C (parallel): F5, F6, F7  — no file overlap
```

### Step 4: Register Dependencies

```bash
bd dep add <F3-id> <F1-id>   # F3 depends on F1 (same file)
```

## Phase 4: Execute in Priority Waves

Execute findings wave by wave: MUST FIX → SHOULD FIX → CONSIDER → NIT.

### Within Each Wave

1. **Dispatch parallel agents** for each non-conflicting group using the Task tool with `subagent_type=general-purpose`. Each agent gets the full self-contained task description from Phase 2.

2. **Agent prompt structure:**
   ```
   You are fixing a code review finding. Follow the resolution steps exactly.

   {full task description from Phase 2}

   IMPORTANT:
   - Follow the resolution steps in order
   - For bugs: write the failing test BEFORE fixing code
   - Run all verification commands listed in acceptance criteria
   - Report back: what you changed, test results, any issues encountered
   ```

3. **Collect results** from all agents in the group.

4. **Sequential groups**: After a parallel group completes, dispatch the next group that depended on it.

5. **Close completed tasks**: `bd close <id>` for each successfully resolved finding.

### Quality Gate Between Waves

Before moving to the next wave, run:

```bash
cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

If anything fails, fix it before proceeding. Do not let failures from Wave 1 propagate into Wave 2.

### Handling `--plan-only` Mode

If invoked with `--plan-only`, stop after Phase 3. Present the task list, dependency graph, and execution plan without dispatching agents. The user can then:
- Reorder or remove tasks
- Adjust groupings
- Execute manually or re-invoke without `--plan-only`

## Phase 5: Summary Report

After all waves complete, present:

```markdown
## Review Findings Execution Summary

**Source**: {source description}
**Total findings**: N
**Executed**: X resolved, Y skipped, Z failed

### Results

| # | Finding | Severity | Status | Task ID | Notes |
|---|---------|----------|--------|---------|-------|
| F1 | Off-by-one in window check | MUST FIX | Resolved | beads-xxx | TDD: test added + fix |
| F2 | Missing capacity hint | SHOULD FIX | Resolved | beads-yyy | 12% alloc reduction |
| F3 | Unclear doc comment | CONSIDER | Resolved | beads-zzz | Updated doc |
| F4 | Rename variable | NIT | Skipped | - | User opted out |

### Verification

- All tests passing: yes/no
- Clippy clean: yes/no
- New tests added: N
- Files modified: [list]
```

## Anti-Patterns

| Anti-Pattern | Why It's Wrong | Do This Instead |
|--------------|----------------|-----------------|
| Fixing a bug without a failing test first | You don't know if the fix works or if the bug was real | TDD: failing test → fix → green |
| Putting multiple findings in one task | Agents lose focus, partial completion is messy | One `bd create` per finding |
| Skipping documentation findings | Doc debt compounds silently | Documentation findings are never optional |
| Dispatching agents that write to the same file | Merge conflicts and lost work | Concurrency analysis in Phase 3 |
| Task description says "see review for details" | Fresh agent can't work it — context is lost | Self-contained descriptions with full context |
| Running all severities in parallel | A MUST FIX might invalidate a NIT | Execute in priority waves |
| Skipping the quality gate between waves | Broken state cascades into subsequent fixes | `cargo test` + clippy between every wave |

## Configuration

| Flag | Effect |
|------|--------|
| `--plan-only` | Stop after Phase 3 — show tasks and execution plan, don't execute |
| `--wave=N` | Execute only wave N (1=MUST FIX, 2=SHOULD FIX, 3=CONSIDER, 4=NIT) |
| `--skip=nit` | Skip NIT-severity findings entirely |
| `--skip=consider,nit` | Skip both CONSIDER and NIT findings |
| `--dry-run` | Parse and normalize findings without creating beads tasks |

## Related Skills

- `/review-dispatch` — produces the findings this skill consumes
- `/pr-comment-response` — TDD verify-first pattern for individual PR comments
- `/bench-compare` — baseline/comparison benchmarks for performance findings
- `/test-strategy` — choose appropriate test type (unit, property, fuzz, Kani)
