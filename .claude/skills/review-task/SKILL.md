---
name: review-task
description: Use when a beads task exists and needs validation before implementation — verifies codebase references, identifies edge cases and design flaws, assesses scope and feasibility, splits oversized tasks, dispatches domain-specific skills (test-strategy, unsafe-review, dist-sys-auditor, simd-optimize, asm-forge, performance-analyzer, security-reviewer, interface-design-review, sim-review, safe-over-unsafe) for specialized enrichment, and dispatches /deep-research or /deeper-research for ambiguous areas. The complement of /create-task — ensures tasks are buttoned up and ready for mechanical implementation.
---

# Review Task

Audits and enriches beads tasks created by `/create-task` (or any source) so that
when a developer picks up the work, they can focus purely on implementation. Catches
stale references, missing edge cases, scope bloat, design flaws, ambiguity, and
*unjustified complexity* — while changes are still cheap (editing a description vs.
reworking code).

**Core principle:** A task that survives this review should require zero research
from the implementing developer. They read, they code, they ship.

**Simplicity principle (MANDATORY):** Every reviewed task must bias toward the
*minimum viable change*. Review uses the `/reduce-complexity` framework to
distinguish essential complexity (domain-inherent, leave alone) from accidental
complexity (reducible). Accidental complexity in the proposed approach MUST be
flagged as MAJOR or BLOCKER, not a nit. New abstractions, config knobs, traits,
or modules require justification by ≥2 concrete current call sites; "future
flexibility" is not a justification and should be rejected.

**Key capability:** Domain-specific skills (testing, unsafe, distributed systems,
SIMD, performance, security, etc.) are dispatched automatically when the task
touches their domain. This adds specialized depth that generalist reviewers
cannot provide.

## Invocation

```
/review-task <task-id>
/review-task <task-id> --deep                 # Dispatch /deep-research for gaps
/review-task <task-id> --deeper               # Dispatch /deeper-research for gaps
/review-task <task-id> --split-only           # Skip verification, assess scope and split
/review-task <task-id> --dry-run              # Print findings without modifying the task
/review-task <task-id> --skip=performance     # Drop a specialist
/review-task <task-id> --focus=distributed    # Adds domain context to all agents
```

**Flags:**

| Flag | Effect |
|------|--------|
| `--deep` | Dispatch `/deep-research` for any identified knowledge gaps |
| `--deeper` | Dispatch `/deeper-research` for critical knowledge gaps |
| `--split-only` | Skip verification phases, assess scope and split if needed |
| `--dry-run` | Print all findings and proposed edits without modifying the task |
| `--skip=<agent>` | Drop a specialist (references, edge-cases, feasibility, scope). Min 2 must run. |
| `--focus=<domain>` | Adds domain context to all agent prompts (e.g., `distributed`, `concurrency`, `unsafe`) |
| `--no-research` | Never dispatch research skills, even if gaps are found (just flag them) |
| `--no-domain` | Skip domain skill enrichment (Phase 1.5). Only run generalist verification. |
| `--domain=<skill>` | Force-dispatch a specific domain skill regardless of auto-detection (e.g., `--domain=test-strategy`) |

---

## Phase 0 — Load & Understand

1. **Fetch the task:**
   ```bash
   bd show <task-id>
   ```

2. **Parse the task description** and extract:
   - Title, type, priority, labels
   - All file paths and line numbers referenced
   - All struct/trait/function/type names mentioned
   - All code snippets embedded in the description
   - Acceptance criteria
   - Related tasks and dependencies
   - Any `[NEEDS ENRICHMENT]` markers from `/create-task`

3. **Quick pre-flight checks** (fail fast):
   - If the task has no description or a stub description (< 5 lines), tell the
     user and recommend running `/create-task` first. Stop.
   - If the task is already closed, warn and ask before proceeding.

4. **Build a Review Brief:**
   ```markdown
   ## Review Brief

   ### Task
   - **ID**: {task-id}
   - **Title**: {title}
   - **Type**: {type} | **Priority**: P{priority}
   - **Labels**: {labels}

   ### Referenced Files
   | File | Lines | Exists? |
   |------|-------|---------|
   {for each file path in the description, check with Glob/ls}

   ### Referenced Identifiers
   | Name | Kind | Found? | Location |
   |------|------|--------|----------|
   {for each type/function/trait name, Grep the codebase}

   ### NEEDS ENRICHMENT Markers
   {list any sections marked as needing enrichment}

   ### Scope Indicators
   - Files referenced: {count}
   - Modules crossed: {count of distinct top-level crate directories}
   - Has acceptance criteria: {yes/no}
   - Has code snippets: {yes/no}
   - Description length: {line count}

   ### Domain Signals
   {detected domain signals — see Domain Skill Dispatch Table below}
   ```

5. **Detect domain signals** for Phase 1.5 enrichment. Scan the task
   description AND referenced files for the triggers listed in the Domain
   Skill Dispatch Table (below). Record which skills should be dispatched.

6. If `--split-only`, skip to Phase 3 (Scope Assessment agent only).

---

## Phase 1 — Verification (3-4 Parallel Agents)

Launch **all selected agents in a single message** using the Task tool with
`subagent_type=general-purpose`. Each agent gets the full task description +
Review Brief but a different verification lens.

### Common Preamble (included in every agent's prompt)

```
You are a specialist task reviewer. You have ONE job: review the task below
through the lens of {SPECIALTY}. Ignore issues outside your specialty — other
specialists cover those.

## Task Under Review

{FULL_TASK_DESCRIPTION}

## Review Brief

{REVIEW_BRIEF}

## Rules

- Only report findings within your specialty. Do NOT stray.
- Only report findings that REQUIRE action. No nits, no "nice to have."
- Be concrete: cite the specific task section, quoted text, file path, or code
  snippet for every finding.
- Explore the codebase (Glob, Grep, Read) to ground findings in reality. The
  most valuable findings come from gaps between what the task says and what the
  codebase actually contains.
- For each finding, state the PROBLEM and the RECOMMENDED FIX (specific text
  to add, remove, or change in the task description).
- Rate each finding:
  - severity: BLOCKER / MAJOR / MINOR
    - BLOCKER: task cannot be implemented as written (wrong file paths, incorrect
      API, missing critical context)
    - MAJOR: task can be implemented but will likely produce incorrect or
      incomplete results (missing edge case, stale pattern, design flaw)
    - MINOR: task is implementable but could be clearer or more complete
  - confidence (0-100): How sure are you this is a real issue?

## Output Format

Return a markdown document starting with:
`# {SPECIALTY} Review`

Then a findings list. For each finding:

### Finding N: {title}

- **Task section**: {which part of the task description}
- **Problem**: {what's wrong or missing}
- **Evidence**: {codebase evidence — file paths, actual code, grep results}
- **Recommended fix**: {specific edit to the task description}
- **Severity**: {BLOCKER / MAJOR / MINOR}
- **Confidence**: {N}%

End with: "Total findings: N" (0 is valid — do not invent issues).
```

---

### Agent 1 — Reference Accuracy

```
Your specialty: REFERENCE ACCURACY

Focus exclusively on:
- Do all file paths in the task exist? Have any moved or been renamed?
- Do line numbers match? Read cited files and verify the code at those lines
  matches what the task quotes.
- Do referenced struct names, trait names, function signatures, enum variants,
  and type aliases actually exist in the codebase?
- Are code snippets in the task accurate copies of the current codebase, or
  have they drifted?
- Does the task reference design docs? If so, does the design doc content
  match what the task claims?
- Are dependency/crate references current (Cargo.toml)?
- Do referenced beads task IDs in the "Related Work" section exist?
  Run `bd show <id>` for each.

For every file path: Read the file. For every code snippet: compare character
by character. For every type name: Grep the codebase. Be exhaustive.

Do NOT review edge cases, design quality, or scope — other specialists do that.
```

---

### Agent 2 — Edge Cases & Completeness

```
Your specialty: EDGE CASES & COMPLETENESS

Focus exclusively on:
- What inputs, states, or conditions does the task not address?
  - Empty/zero/nil inputs
  - Boundary values (max capacity, zero-length, single element)
  - Concurrent access patterns if the code is shared across threads
  - Error paths and failure modes not mentioned
  - Rollback/cleanup on partial failure
- Does the "Desired State" cover ALL cases, or only the happy path?
- Are the acceptance criteria specific enough to verify? Could an
  implementer satisfy the criteria while missing the actual intent?
- Does the task account for existing callers/consumers of modified APIs?
  (Grep for call sites the task doesn't mention)
- Are there related invariants documented in design docs or code comments
  that the task should preserve but doesn't mention?
- Does the implementation guidance miss files that will obviously need
  changes? (e.g., mod.rs re-exports, test files, Cargo.toml features)

For each edge case found: describe the scenario, explain what would go wrong,
and propose a specific addition to the task description.

Do NOT review reference accuracy, design alternatives, or scope — other
specialists do that.
```

---

### Agent 3 — Feasibility, Design & Simplicity

```
Your specialty: FEASIBILITY, DESIGN & SIMPLICITY

Apply the /reduce-complexity framework (essential vs. accidental complexity)
to every design decision the task proposes. The simplest correct solution
wins. Any complexity the task introduces must be justified as essential; if
it is accidental, flag it as MAJOR or BLOCKER.

Focus exclusively on:
- Is the proposed approach actually feasible given the codebase architecture?
  Read the relevant modules and assess whether the task's implementation
  guidance is compatible with existing patterns.
- SIMPLICITY CHECK — Is there a materially simpler approach? Apply these
  tests from /reduce-complexity to the PROPOSED design, not just existing code:
    1. Domain necessity: Would a clean-room reimplementation of the same
       requirement have similar structure? If no, complexity is accidental.
    2. Reuse check: Does an existing utility in `src/utils.rs`, a sibling
       module, or a trait impl already solve this? Extending is almost
       always simpler than creating.
    3. Extraction check: Does the task propose a new function/trait/module
       that would have only 1 call site? That's premature abstraction.
    4. Parameter check: Does a new function take ≥6 parameters? Likely
       signals two concerns merged into one.
    5. Delete-first check: Could the requirement be satisfied by REMOVING
       code rather than adding it? Always consider deletion first.
- Does the approach introduce unnecessary complexity? (New abstractions,
  generics, indirection, config knobs, traits not driven by ≥2 call sites)
- Could any step in Desired State be collapsed, merged, or deleted?
- Does the task propose a new module/file when the logic fits naturally in
  an existing one? (Unnecessary fragmentation is accidental complexity.)
- Are there performance concerns the task should flag?
  - Hot path allocations (check if touched code is in HOT tier)
  - Lock contention or oversized critical sections
  - Unbounded growth patterns
- Does the approach contradict any project conventions?
  - No-versioning policy (no V1/V2, no deprecated, no compatibility shims)
  - Allocation policy tiers (HOT/WARM/COLD)
  - Comment policy (no tracking IDs, no temporal narration)
- Are there design trade-offs the task should document but doesn't?
- Will the approach compose well with in-flight work? Check `bd list --status=in_progress`
  for potentially conflicting changes.

Classification rubric for simplicity findings:
- BLOCKER: Task proposes an abstraction/module/knob with zero or one current
  call site; or proposes reimplementing an existing utility.
- MAJOR: Task adds a layer of indirection that a direct call would replace;
  or crosses an extra module boundary without benefit.
- MINOR: Wording in Desired State implies unnecessary generality ("configurable",
  "pluggable") without concrete current need.

Do NOT review reference accuracy, edge case enumeration, or scope — other
specialists do that.
```

---

### Agent 4 — Scope Assessment

```
Your specialty: SCOPE ASSESSMENT

Focus exclusively on:
- Is this task appropriately sized for a single implementation session?
  A well-scoped task modifies 1-4 files in 1-2 modules. Flag if it exceeds:
  - 6+ files modified
  - 3+ modules crossed
  - 3+ distinct behavioral changes
  - Both production code AND test infrastructure changes that could be separate
- Can this task be decomposed into independent sub-tasks that deliver
  incremental value? If so, propose specific splits with:
  - Sub-task title
  - Which files/sections of the original task belong to each
  - Dependency ordering between sub-tasks
  - Whether each sub-task is independently testable
- Does the task mix concerns? Common anti-patterns:
  - Refactor + new feature in one task
  - Bug fix + performance optimization in one task
  - API change + migration of all callers in one task
- Are there prerequisite tasks that should be extracted?
  (e.g., "add trait X" before "implement trait X for types A, B, C")
- Is the task UNDER-scoped? Does it describe a change that won't be useful
  without follow-up work that isn't tracked?

For each scope finding, provide a concrete split recommendation with titles,
file assignments, and dependency ordering.

Do NOT review reference accuracy, edge cases, or design quality — other
specialists do that.
```

---

## Phase 1.5 — Domain Enrichment

After Phase 1 specialists complete but before synthesis, dispatch domain-specific
skills to provide specialized depth. Skip this phase if `--no-domain` is set.

### Domain Skill Dispatch Table

The orchestrator detects signals from the task description, referenced files,
and Phase 1 findings to determine which domain skills to dispatch. Maximum
**3 domain skills** per review to keep scope manageable.

| Signal | Skill | What It Adds to the Task |
|--------|-------|--------------------------|
| Task mentions testing strategy, or acceptance criteria lack test type guidance, or task touches code with no test coverage | `/test-strategy` | Specific test types (unit, rstest, proptest, fuzz, Kani, sim), patterns, and commands |
| Referenced files contain `unsafe` blocks, or task adds new unsafe code | `/unsafe-review` | Safety invariant audit, test coverage matrix (Miri/Kani/fuzz/proptest gaps) |
| Task adds unsafe AND needs safe public API wrapping | `/safe-over-unsafe` | API boundary design, module privacy soundness checklist |
| Referenced files are in `modules touching proxy/cache logic → `/performance-analyzer`
| Task touches coordination AND mentions simulation or fault tolerance | `/sim-review` | DST compatibility check, sans-IO pattern enforcement |
| Task is labeled performance or touches HOT-tier code paths, or Phase 1 feasibility agent flagged performance concerns | `/performance-analyzer` | Allocation audit, cache analysis, hot-path verification |
| Task involves SIMD, vectorization, or `std::arch` intrinsics | `/simd-optimize` | ISA detection, pattern classification, implementation strategy |
| Task involves assembly-level optimization or codegen quality | `/asm-forge` | ASM audit scope, codegen red flags to include in task guidance |
| Task modifies public API surface (`pub fn`, `pub struct`, `pub trait`) | `/interface-design-review` | Misuse-resistance audit, enforcement hierarchy check |
| Task touches parsing, buffer handling, or security-sensitive operations | `/security-reviewer` | Memory safety audit, CWE mapping, high-risk file identification |
| Task modifies any file flagged HIGH/CRITICAL by /reduce-complexity, OR proposes a new abstraction, OR Phase 1 feasibility agent flagged accidental complexity, OR task claims to "refactor" or "simplify" | `/reduce-complexity` | LOC/nesting/parameter hotspots on affected files, essential vs. accidental classification, concrete reduction suggestions, anti-abstraction brake checks |

### Detection Logic

1. **File-based signals**: For each referenced file, check which crate and
   module it belongs to. Map to domain skills:
   - `modules touching proxy/cache logic → `/performance-analyzer`
   - `src/utils.rs/src/` data structures with unsafe → `/unsafe-review`
   - `src/` hot paths → `/performance-analyzer`
   - Files containing `std::arch::` or SIMD intrinsics → `/simd-optimize`

2. **Content-based signals**: Grep the task description for keywords:
   - "unsafe", "SAFETY:", "raw pointer", "MaybeUninit" → `/unsafe-review`
   - "lease", "epoch", "fence", "shard", "cursor", "coordination" → `/dist-sys-auditor`
   - "SIMD", "vectorize", "intrinsic", "NEON", "AVX" → `/simd-optimize`
   - "benchmark", "latency", "throughput", "hot path", "allocation" → `/performance-analyzer`
   - "test strategy", "property test", "fuzz", "simulation" → `/test-strategy`
   - "public API", "trait", "builder", "interface" → `/interface-design-review`
   - "refactor", "simplify", "cleanup", "reduce complexity", "too complex",
     "new abstraction", "new trait", "new module", "extensible", "flexible",
     "future-proof", "configurable" → `/reduce-complexity`

3. **Phase 1 escalation**: If a Phase 1 specialist flags a domain-specific
   concern that they cannot fully evaluate (e.g., feasibility agent says "this
   touches unsafe code but I can't assess soundness"), escalate to the
   corresponding domain skill.

4. **Forced dispatch**: If `--domain=<skill>` is set, always include that
   skill regardless of auto-detection.

5. **Priority when > 3 skills triggered**: Rank by relevance to the task type:
   - Bug tasks: prioritize `/test-strategy`, `/unsafe-review`, `/security-reviewer`
   - Feature tasks: prioritize `/interface-design-review`, `/reduce-complexity`, `/test-strategy`
   - Performance tasks: prioritize `/performance-analyzer`, `/asm-forge`, `/simd-optimize`
   - Safety tasks: prioritize `/unsafe-review`, `/safe-over-unsafe`, `/security-reviewer`
   - Refactor/simplify tasks: prioritize `/reduce-complexity`, `/dedup-audit`, `/interface-design-review`

**Mandatory inclusion:** `/reduce-complexity` is always a candidate. Include it
whenever the task introduces new abstraction, new module, new trait, a new
config knob, generalization, or is labeled "refactor"/"simplify" — even if no
other signal fires.

### Dispatch Protocol

For each selected domain skill, the orchestrator:

1. **Invokes the skill** with a scoped prompt. The skill receives:
   - The full task description
   - The specific files/code relevant to its domain (not the entire codebase)
   - A directive to produce an **enrichment report** (not a full audit):

   > You are being invoked as a domain enrichment step during task review.
   > Your job is NOT to do a full audit. Instead, produce a focused report
   > answering: "What domain-specific information should be added to this
   > task description to make it implementable without further research?"
   >
   > Specifically:
   > - What domain-specific edge cases or gotchas does the task miss?
   > - What domain-specific patterns, utilities, or conventions should it reference?
   > - What domain-specific acceptance criteria should be added?
   > - What domain-specific risks should be called out?
   >
   > Keep output concise — aim for 5-15 specific, actionable items.

2. **Collects the enrichment report** and passes it to the Phase 2
   synthesizer alongside the Phase 1 specialist reports.

### Parallel Dispatch

If multiple domain skills are selected, dispatch them **in parallel in a
single message** — they operate on different domains and don't conflict.

If a domain skill invocation fails or times out, proceed without it. Record
the failure in the synthesis so the user knows what enrichment was skipped.

---

## Phase 2 — Synthesize Findings (Single Agent)

After Phase 1 specialists AND Phase 1.5 domain enrichment complete, launch
**1 synthesizer agent** using the Task tool with `subagent_type=general-purpose`.

### Synthesizer Prompt

```
You are the Task Review Synthesizer. Specialist reviewers have independently
audited the same beads task, and domain-specific skills have provided
specialized enrichment. Your job is to merge ALL inputs into one actionable
report and determine whether the task needs revision, research, splitting,
or is ready for implementation.

## Original Task
{FULL_TASK_DESCRIPTION}

## Specialist Reports (Phase 1)
{ALL_SPECIALIST_REPORTS}

## Domain Enrichment Reports (Phase 1.5)
{ALL_DOMAIN_ENRICHMENT_REPORTS}
(or "No domain skills dispatched" if Phase 1.5 was skipped)

## Your Task

### 1. Deduplicate

Multiple specialists may flag the same underlying issue from different angles.
Group these into single findings and note which specialists flagged it.

### 2. Score & Filter

For every unique finding, assess:

- **Severity**: BLOCKER / MAJOR / MINOR
  - BLOCKER: Task cannot be correctly implemented as written
  - MAJOR: Implementation will likely produce incorrect or incomplete results
  - MINOR: Task is implementable but could be clearer
- **Confidence** (0-100): How sure is this a real issue?

Discard any finding with confidence < 50. Every finding in the final report
must require action.

### 3. Integrate Domain Enrichment

For each domain enrichment report, extract actionable items and classify:

- **Add to task**: Domain-specific edge cases, patterns, conventions,
  acceptance criteria, or risk callouts that should be folded into the task
  description.
- **Contradicts task**: Domain skill found something that conflicts with the
  task's proposed approach. Elevate to a MAJOR or BLOCKER finding.
- **Confirms task**: Domain skill validated the approach. Note as supporting
  evidence (no action needed).

### 4. Classify Into Verdicts

Based on the surviving findings (from both specialists and domain enrichment),
assign the task ONE overall verdict:

- **READY**: 0 BLOCKERs, 0-2 MAJORs, task is implementable. List MINORs as
  optional improvements.
- **REVISE**: 0 BLOCKERs, but 3+ MAJORs or significant gaps, or domain
  enrichment produced items that should be folded into the task. Task needs
  specific edits before implementation.
- **RESEARCH**: Findings reveal ambiguity or unknowns that cannot be resolved
  by reading the codebase alone — external research is needed. Flag specific
  questions for `/deep-research` or `/deeper-research`.
- **SPLIT**: Task scope is too large for a single implementation session.
  Propose concrete sub-tasks.
- **REWORK**: 2+ BLOCKERs. Task description is fundamentally flawed. Recommend
  re-running `/create-task` with corrected information.

A task can receive multiple verdicts (e.g., REVISE + SPLIT).

### 5. Research Questions (if verdict includes RESEARCH)

For each knowledge gap that requires external research:

- **Question**: {specific question that needs answering}
- **Why it matters**: {impact on the implementation}
- **What we know**: {best available evidence from the codebase}
- **What's missing**: {the specific gap}
- **Recommended skill**: `/deep-research` or `/deeper-research`
- **Suggested problem statement**: {ready-to-paste prompt for the research skill}

### 6. Split Recommendations (if verdict includes SPLIT)

For each proposed sub-task:

- **Title**: {imperative statement}
- **Scope**: {which files and sections from the original task}
- **Dependencies**: {which sub-tasks must complete first}
- **Independently testable**: {yes/no}
- **Priority relative to original**: {same / higher / lower}

### 7. Revision Checklist (if verdict includes REVISE)

A numbered list of specific edits to make to the task description. Include
both specialist-sourced revisions and domain enrichment items:

1. {section} — {what to change and why} — source: {specialist / domain skill}
2. ...

Each item must be concrete enough that the edit can be made mechanically.

### Output Format

```markdown
## Task Review Report

**Task**: {id} — {title}
**Verdict**: {READY / REVISE / RESEARCH / SPLIT / REWORK}
**Findings**: {N total — X BLOCKERs, Y MAJORs, Z MINORs}
**Domain skills dispatched**: {list or "none"}

### Findings

| # | Finding | Severity | Confidence | Source |
|---|---------|----------|------------|--------|

**Details:**

#### 1. {Finding title}
- **Problem**: {description}
- **Evidence**: {codebase evidence}
- **Recommended fix**: {specific edit}
- **Source**: {specialist name and/or domain skill name}

### Domain Enrichment Summary

| Domain Skill | Items to Add | Contradictions | Confirmations |
|--------------|-------------|----------------|---------------|
| /test-strategy | 3 | 0 | 1 |
| /unsafe-review | 2 | 1 | 0 |

{Details of each domain enrichment item}

### {Verdict-specific sections as applicable}
```

### Rules

- Do NOT add your own findings — synthesize, don't review.
- If a specialist's finding seems wrong, lower its confidence. If it drops
  below 50%, discard it.
- Preserve file paths and codebase citations from specialist reports.
- Be honest about the verdict. Do not inflate READY to avoid work. A task
  that ships with BLOCKERs wastes more time than revising the description.
```

---

## Phase 3 — Act on Verdict

Based on the synthesizer's verdict, take the appropriate action. If `--dry-run`
is active, print the proposed actions without executing them.

### Verdict: READY

Present the report to the user. No modifications needed.

```
Task {id} passed review.
Verdict: READY
Findings: {summary — e.g., "2 MINORs (optional improvements)"}

{list MINORs if any, as optional suggestions}
```

### Verdict: REVISE

Apply the revision checklist to the task description:

1. Read the current task description: `bd show <task-id>`
2. Apply each revision from the checklist.
3. If `--dry-run`, print the diff and stop.
4. Update the task: `bd update <task-id> --description="..."`
5. Show the updated task to the user.

```
Task {id} revised.
Verdict: REVISE
Changes applied: {count}
{summary of each change}
```

### Verdict: RESEARCH

Dispatch the appropriate research skill for each identified gap:

1. If `--no-research` is set, present the research questions to the user
   and stop. The user can manually run `/deep-research` or `/deeper-research`.

2. If `--deep` is set (or inferred from the gap severity):
   - Invoke `/deep-research` with the suggested problem statement.
   - After research completes, fold key findings into the task description:
     add them to the Implementation Guidance, Design Notes, or Risk Analysis
     sections as appropriate.
   - Update the task: `bd update <task-id> --description="..."`

3. If `--deeper` is set (for critical/highest-stakes gaps):
   - Invoke `/deeper-research` with the suggested problem statement.
   - Fold findings into the task description as above.
   - Update the task.

4. After research is folded in, re-run Phase 1-2 (without the research
   dispatch) to verify the enriched task is now READY or REVISE.

### Verdict: SPLIT

Create sub-tasks from the split recommendations:

1. For each proposed sub-task:
   - Extract the relevant sections from the original task description.
   - Create a new task using `/create-task --quick` with the extracted scope.
     Use `--quick` because the context already exists — no need for fresh
     research.
   - Register dependencies: `bd dep add <child-id> <dependency-id>`
   - Set the parent: if the original task is an epic, use `--parent=<original-id>`.
     Otherwise, convert the original task to an epic first:
     `bd update <original-id> --type=epic`

2. Present the split to the user:
   ```
   Task {id} split into {N} sub-tasks:

   {original-id} (epic): {original title}
   ├── {child-1-id}: {title} [no dependencies]
   ├── {child-2-id}: {title} [depends on {child-1-id}]
   └── {child-3-id}: {title} [depends on {child-1-id}]
   ```

3. If `--dry-run`, print the proposed sub-tasks with descriptions without
   creating them.

### Verdict: REWORK

Do NOT attempt to patch the task. Present the findings and recommend
re-running `/create-task`:

```
Task {id} needs rework.
Verdict: REWORK ({N} BLOCKERs found)

BLOCKERs:
1. {finding title}: {problem}
2. {finding title}: {problem}

Recommendation: Re-run /create-task with corrected context. Key corrections:
- {what was wrong in the original task}
- {what the correct information is}
```

### Compound Verdicts

When multiple verdicts apply (e.g., REVISE + SPLIT):

1. Apply REVISE first (fix the content).
2. Then apply SPLIT (decompose the corrected task).
3. If RESEARCH is part of the compound, research first, then revise, then split.

Order: RESEARCH → REVISE → SPLIT. REWORK supersedes all others.

---

## Convergence Defaults

Use **fast mode** (2 agents) when all of these are true:

- Task modifies <= 3 files
- Task crosses <= 1 module boundary
- No unsafe code, concurrency, or distributed systems concerns
- Task type is not `epic`
- No `[NEEDS ENRICHMENT]` markers

Fast mode agents: **Reference Accuracy** + **Edge Cases & Completeness**.

Use **standard mode** (4 agents) for everything else.

---

## Anti-Patterns

| Anti-Pattern | Why It's Wrong | Do This Instead |
|--------------|----------------|-----------------|
| Approving a task with stale file paths | Implementer wastes time finding moved code | Verify every path with Glob/Read |
| Adding findings without codebase evidence | Speculation wastes revision effort | Grep and Read before claiming a problem |
| Splitting a task that's already well-scoped | Creates overhead without benefit | Only split when scope criteria are exceeded |
| Patching a fundamentally broken task | Lipstick on a pig — BLOCKERs compound | REWORK verdict, re-run /create-task |
| Running /deeper-research for simple gaps | Token-expensive overkill | Use /deep-research for standard gaps, codebase reading for simple ones |
| Skipping review for "obvious" tasks | Obvious tasks have the most hidden assumptions | Review everything; fast mode exists for small tasks |
| Revising without showing the user | User loses visibility into what changed | Always present changes before or after applying |
| Dispatching 5+ domain skills | Context overload, diminishing returns | Cap at 3 domain skills, prioritize by task type |
| Running domain skills on tasks with no domain-specific code | Wasted tokens, noise in the report | Let auto-detection decide; only force with --domain when justified |
| Ignoring domain skill contradictions | Domain expert found a real problem the generalist missed | Always elevate contradictions to findings |

## Related Skills

**Complementary pair:**
- `/create-task` — creates the tasks this skill reviews

**Research (dispatched for knowledge gaps in Phase 3):**
- `/deep-research` — 7-agent research for standard gaps
- `/deeper-research` — 21-agent research for critical gaps

**Domain enrichment (dispatched in Phase 1.5):**
- `/reduce-complexity` — essential vs. accidental complexity framework; always a candidate when abstractions, modules, or "refactor"/"simplify" language appear
- `/test-strategy` — test type recommendations (unit, rstest, proptest, fuzz, Kani, sim)
- `/unsafe-review` — safety invariant audit, test coverage matrix
- `/safe-over-unsafe` — safe API boundary design for unsafe internals
- `/dist-sys-auditor` — distributed systems citation and invariant verification
- `/sim-review` — deterministic simulation testability compliance
- `/performance-analyzer` — allocation, cache, and CPU hotspot analysis
- `/simd-optimize` — SIMD pattern classification and ISA strategy
- `/asm-forge` — assembly codegen quality audit
- `/interface-design-review` — API misuse-resistance enforcement
- `/security-reviewer` — memory safety and CWE mapping

**Downstream:**
- `/plan-review` — reviews implementation plans (this skill reviews task descriptions)
- `/plan-forge` — creates implementation plans from tasks
- `/review-dispatch` — reviews code after implementation
- `/execute-review-findings` — executes review findings as tasks
