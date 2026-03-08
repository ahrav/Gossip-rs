---
name: design-doc-audit
description: Use when design documents in docs/ may be stale after code changes,
  when verifying boundary specs match current types and APIs, when checking for
  missing documentation coverage of new crates or features, or before merging
  branches that touch documented subsystems.
user-invocable: true
---

# Design Doc Audit

A verify-first audit of design documents in `docs/` against the current codebase.
Parallel specialist agents each audit a subset of design docs against the actual
source code, then a synthesizer merges findings into a prioritized report with
auto-fix for trivial drift.

**Core principle:** Every claim in a design document is a hypothesis. Verify it
against the code before declaring it correct or incorrect.

**Scope boundary:** This skill audits standalone design documents in `docs/` — the
architecture specs, boundary contracts, and feature descriptions that describe
system behavior at a higher level. It does NOT audit:
- `diagrams/` Mermaid files (use `/doc-code-audit` for that)
- Inline `///` docstrings in source files (use `/doc-verify` for that)

## When to Use

- After significant code changes to verify design docs still match reality
- Before merging a branch that touches documented subsystems
- When verifying boundary specs match current types, traits, and APIs
- When checking for missing documentation coverage of new crates or features
- Periodic hygiene audits to catch design doc drift
- After adding new source files to directories covered by existing design docs

## When NOT to Use

- For auditing Mermaid diagrams (use `/doc-code-audit`)
- For verifying inline code docstrings (use `/doc-verify`)
- For writing new documentation from scratch (use `/doc-rigor`)
- For reviewing code quality (use `/review-dispatch`)

## Invocation

```
/design-doc-audit [<scope>] [--flags]
```

### Positional Argument: Scope

The scope determines which docs and source directories are audited. If omitted,
defaults to `--incremental` mode (changes since last docs update).

**Domain scopes** (audit a specific boundary or feature area):

| Scope | Docs | Source Directories |
|-------|------|--------------------|
| `coordination` | `gossip-coordination/boundary-2-coordination.md`, `coordination-testing.md`, `simulation-harness.md`, `coordination-error-model.md` | `gossip-contracts/src/coordination/`, `gossip-coordination/src/` |
| `etcd` | `gossip-coordination/boundary-2-coordination.md` (etcd sections) | `gossip-coordination-etcd/src/` |
| `persistence` | `gossip-contracts/boundary-5-persistence.md`, `gossip-persistence-inmemory.md` | `gossip-contracts/src/persistence/`, `gossip-persistence-inmemory/src/` |
| `identity` | `gossip-contracts/boundary-1-identity-spine.md` | `gossip-contracts/src/identity/` |
| `connectors` | `gossip-connectors/boundary-4-connectors.md` | `gossip-contracts/src/connector/`, `gossip-connectors/src/` |
| `shard-algebra` | `gossip-contracts/boundary-3-shard-algebra.md`, `gossip-frontier/shard-algebra.md` | `gossip-frontier/src/` |
| `scanning` | `scanner-engine/`, `scanner-scheduler/`, `scanner-git/` | `scanner-engine/src/`, `scanner-scheduler/src/`, `scanner-git/src/` |
| `findings` | `gossip-contracts/boundary-5-persistence.md` | `gossip-contracts/src/persistence/findings.rs` |
| `done-ledger` | `gossip-contracts/boundary-5-persistence.md` | `gossip-contracts/src/persistence/done_ledger.rs` |
| `overview` | `architecture-overview.md` | (cross-cutting) |

**File paths** — audit specific files directly:

```
/design-doc-audit docs/gossip-coordination/boundary-2-coordination.md
/design-doc-audit docs/gossip-contracts/boundary-5-persistence.md docs/gossip-persistence-inmemory.md
```

### Flags

| Flag | Default | Effect |
|------|---------|--------|
| `--full` | off | Audit all design docs, not just incrementally affected ones |
| `--scope=<s>` | all | Comma-separated domain filter (e.g., `--scope=coordination,etcd`) |
| `--strict` | off | Treat all findings as errors (fail on any finding) |
| `--no-auto-fix` | off | Skip auto-fix phase, report only |
| `--summary` | off | Output only summary tables, suppress detailed write-ups |

---

## Phase 0 — Scope Resolution (Orchestrator)

Determine which design documents and source directories to audit.

### Incremental Mode (default)

1. Find the last commit that touched any file in `docs/`:
   ```bash
   git log -1 --format='%H' -- docs/
   ```

2. Find all `.rs` files changed since that commit:
   ```bash
   git diff --name-only <last-docs-commit>..HEAD -- '*.rs'
   ```

3. Read `docs/scope-map.toml` and map each changed `.rs` file to its in-scope
   design docs. A file is "in scope" if its repo-relative path starts with a
   scope entry's `dir` value.

4. Deduplicate the doc list. These are the files to audit.

5. If no docs are in scope (all code changes are in undocumented directories),
   report "No design docs in scope of recent code changes" and stop.

### Full Mode (`--full`)

1. Collect all `.md` files in `docs/` and its subdirectories.
2. Exclude `findings/`, `assets/`, and `README.md` files.
3. These are all the files to audit.

### Domain-Scoped Mode (`--scope=<s>`)

Use the domain-to-file mapping table above. Collect the listed docs for the
specified domain(s). Resolve all doc paths relative to `docs/`.

### File-Path Mode

Use the explicitly provided file paths.

### Partition into Agent Batches

Partition the collected doc files into batches of 2-4 files per agent. Group
files from the same domain together when possible. Cap at 5 audit agents.

For each batch, resolve the source directories from `docs/scope-map.toml` —
these are the directories the agent should check against.

---

## Phase 1 — Parallel Audit Agents (up to 5)

Launch all agents **in a single message** using the Agent tool with
`subagent_type=general-purpose`.

### Agent Prompt Template

Each agent receives this prompt with `{DOC_FILES}`, `{SOURCE_DIRS}`, and
`{AUDIT_MODE}` filled in:

```
You are a design-document-vs-code consistency auditor. Your job is to read each
design document, extract every verifiable claim, and check it against the actual
codebase. You are skeptical by default — assume nothing is correct until verified.

## Documents to Audit

{DOC_FILES}

## Source Directories to Check Against

{SOURCE_DIRS}

## Audit Mode: {AUDIT_MODE}

If "incremental": Focus on claims related to recently changed code. The following
.rs files changed since the last docs update:
{CHANGED_RS_FILES}

If "full" or "domain": Check every verifiable claim in the document.

## What to Verify

For each document, systematically extract and verify claims in these categories:

### 1. File Inventories
- Does the doc list specific source files? Do they all exist?
- Does the doc claim "N files" or "N modules"? Count the actual number.
- Are file descriptions accurate? (e.g., "foo.rs contains the retry logic")
- Are any source files in the mapped directories missing from the doc's inventory?

### 2. Type/Struct/Enum Accuracy
- Do named types (structs, enums, traits) exist in code?
- Are field lists accurate? (field names, types, visibility)
- Are variant lists accurate for enums? Does "N variants" match reality?
- Are generic parameters correct?

### 3. Trait & API Accuracy
- Do named traits exist? Are their method signatures accurate?
- Do named functions/methods exist with the documented signatures?
- Are described behaviors correct? (read the actual implementation)
- Do documented error conditions match the code?

### 4. Behavioral Claims
- Are stated invariants enforced in code?
- Do "must always" / "must never" claims hold?
- Are documented preconditions checked?
- Do described state machines match actual state transitions?
- Are lifecycle descriptions accurate?

### 5. Architecture & Dependency Claims
- Do "depends on" / "imports from" claims match Cargo.toml and use statements?
- Are crate-to-boundary mappings accurate?
- Are module organization claims correct?
- Do described data flow paths match the actual call graph?

### 6. Cross-References
- Do links to other docs point to files that exist?
- Are cross-referenced claims consistent between documents?
- Do "source code references" tables list files that exist with accurate descriptions?
- Do referenced diagram files exist?

### 7. Coverage Gaps
- Are there significant types, traits, or modules in the source directories
  that the design doc does not mention at all?
- Are there new public APIs not covered by the doc?
- Has the doc's scope grown stale relative to the code it describes?

## How to Verify

Use these tools to check claims against code:

- `colgrep "<semantic query>" --include="*.rs" <source_dir>` — semantic code search
- `colgrep -e "<exact_name>" --include="*.rs" <source_dir>` — exact name search
- Read specific files when you need to verify function bodies, struct fields,
  or invariant enforcement
- Use Glob to find files when a doc references a file that may have moved
- Use Grep for exact identifier lookups

IMPORTANT: Actually read and understand the relevant code. Do not guess or
assume based on names alone.

## Classification

For each finding, classify it as:

| Category | Meaning | Severity |
|----------|---------|----------|
| INCORRECT | Doc states something that is demonstrably wrong | HIGH |
| STALE | Doc references something that was renamed, moved, or removed | HIGH |
| INCONSISTENT | Doc contradicts itself or another doc | MEDIUM |
| INCOMPLETE | Doc omits something significant that exists in code | MEDIUM |
| ASPIRATIONAL | Doc describes behavior not yet implemented | LOW |
| UNVERIFIABLE | Claim cannot be checked from code alone | INFO |

For STALE findings, note the old name and the new/current name (or "removed").
For INCORRECT findings involving counts, note both the claimed count and actual count.

## Output Format

Return a markdown document:

# Audit: {document_filename}

## Summary
- Claims checked: N
- Findings: X (Y high, Z medium, W low)
- Verdict: CONSISTENT / DRIFT DETECTED / MAJOR INCONSISTENCIES

## Findings

| # | Category | Severity | Doc Line | Claim | Code Reality | File:Line |
|---|----------|----------|----------|-------|-------------|-----------|

## Details

### Finding N: {title}
- **Doc says**: {quote from doc}
- **Code says**: {what the code actually does, with file:line}
- **Evidence**: {how you verified}
- **Suggested fix**: {how to update the doc}
- **Auto-fixable**: yes/no (yes only for file counts, type renames, variant counts)

## Coverage Gaps
- {List any significant source code not mentioned in the doc}

## Verified Claims (sample)
| Claim | Verified Against |
|-------|-----------------|

## Rules

- NEVER report a finding without verifying it against actual code first.
- If you cannot find the relevant code, say so explicitly — do not guess.
- Quote exact doc text and exact code for every finding.
- Distinguish between "the doc is wrong" and "the doc is ambiguous."
- If a doc describes target/aspirational behavior, classify it as ASPIRATIONAL
  only if the doc itself says so. If the doc presents aspirational behavior as
  current fact, classify as INCORRECT.
- For every STALE finding, record old and new identifiers explicitly so the
  orchestrator can attempt auto-fix.
```

---

## Phase 2 — Synthesize & Prioritize (Single Agent)

After all audit agents complete, launch **1 synthesizer agent** using the Agent
tool with `subagent_type=general-purpose`.

### Synthesizer Prompt

```
You are the Design Doc Audit Synthesizer. Multiple audit agents have
independently reviewed design documents against the codebase. Your job is
to merge their findings into one actionable report.

## Agent Reports

{ALL_AGENT_REPORTS}

## Your Task

### 1. Deduplicate

If multiple agents flagged the same underlying issue (e.g., a renamed type
referenced in two different docs), group them as one finding and note all
affected documents.

### 2. Prioritize

Rank findings by impact — how likely is this inconsistency to mislead a
developer or cause incorrect implementation?

Priority criteria:
- **P0 — BLOCK**: Doc states behavior that contradicts code AND could lead to
  bugs if a developer trusts the doc (wrong invariant, wrong error handling,
  wrong state transition)
- **P1 — HIGH**: Doc references types/functions that don't exist, or has wrong
  field/variant lists. Developer would immediately hit compile errors.
- **P2 — MEDIUM**: Internal doc contradictions, incomplete listings, stale
  cross-references. Confusing but not directly dangerous.
- **P3 — LOW**: Aspirational content not clearly labeled, minor naming
  inconsistencies, unverifiable claims.

### 3. Group by Document

Organize findings so the user can fix docs one file at a time.

### 4. Identify Systemic Patterns

If a pattern emerges (e.g., "all coordination docs reference the old
`ShardRecord` type that was renamed to `ShardEntry`"), call it out as a
systemic drift issue rather than listing N individual findings.

### 5. Tag Auto-Fixable Findings

Mark findings that can be auto-fixed:
- **File count claims**: "N files" → update to actual count
- **File inventory tables**: Add missing files, remove phantom files
- **Type/variant counts**: "N variants" → update to actual count
- **Renamed identifiers**: Replace old name with new name in doc text

All other findings require manual review.

### 6. Output Format

## Design Doc Audit Report

**Mode**: {incremental|full|domain:<name>|files}
**Documents audited**: N
**Total findings**: X (P0: A, P1: B, P2: C, P3: D)
**Auto-fixable**: M of X
**Overall verdict**: CONSISTENT / DRIFT DETECTED / MAJOR INCONSISTENCIES

### Executive Summary

{2-3 sentence overview. What areas are clean? Where is the most drift?}

### P0 — Must Fix (doc could cause bugs)

| # | Document | Line | Finding | Code Reality |
|---|----------|------|---------|-------------|

{Detailed write-ups for each P0 finding}

### P1 — Should Fix (stale references)

| # | Document | Line | Finding | Code Reality | Auto-fix? |
|---|----------|------|---------|-------------|-----------|

### P2 — Consider (inconsistencies)

{Table only unless context is needed}

### P3 — Low Priority

{Table only}

### Auto-Fix Manifest

List every auto-fixable finding with the exact replacement:

| # | Document | Line | Current Text | Replacement Text | Fix Type |
|---|----------|------|-------------|-----------------|----------|

Fix types: file-count, file-inventory, type-count, identifier-rename

### Clean Documents

The following documents passed audit with no findings:
- {list of clean docs}

### Coverage Summary

| Document | Claims Checked | Findings | Auto-fixable | Verdict |
|----------|---------------|----------|--------------|---------|

### Systemic Issues

{Patterns that affect multiple docs — suggest `/create-task` for remediation}

### Recommendations

{Actionable next steps}

## Rules

- Present findings directly. Do not soften or filter them.
- If all docs are consistent, say so clearly — a clean audit is valuable info.
- Preserve file:line citations from the agent reports.
- Do NOT add your own findings — you are a synthesizer, not an auditor.
- If an agent's finding seems wrong, note it as "disputed" with your reasoning
  but still include it.
```

---

## Phase 3 — Auto-Fix Simple Cases (Orchestrator)

If `--no-auto-fix` was NOT set and the synthesizer's Auto-Fix Manifest is
non-empty, apply trivial fixes.

### What Can Be Auto-Fixed

| Fix Type | Example | Method |
|----------|---------|--------|
| `file-count` | "contains 7 files" → "contains 9 files" | Edit the number in-place |
| `file-inventory` | Missing file in table → add row | Add row to markdown table |
| `file-inventory` | Phantom file in table → remove row | Remove row from markdown table |
| `type-count` | "5 variants" → "6 variants" | Edit the number in-place |
| `identifier-rename` | `ShardRecord` → `ShardEntry` | Find-and-replace in doc text |

### What Cannot Be Auto-Fixed

- Behavioral claims (wrong invariant descriptions)
- Architectural claims (wrong dependency descriptions)
- State machine descriptions
- Aspirational content mixed with current-state descriptions
- Any finding that requires understanding intent

### Process

For each auto-fixable finding from the manifest:

1. Read the target doc file
2. Locate the exact line referenced
3. Apply the fix using the Edit tool
4. Present each fix to the user for confirmation before applying

If a fix is ambiguous (e.g., the same number appears multiple times on the
line), skip it and flag for manual review.

---

## Phase 4 — Presentation

After synthesis (and optional auto-fix), present the report to the user.

### Report Structure

1. **Verdict banner** at the top:
   - `CONSISTENT` — no findings
   - `DRIFT DETECTED` — findings exist but no P0s
   - `MAJOR INCONSISTENCIES` — P0 findings present

2. **P0 findings** called out prominently if any exist

3. **Executive summary** from the synthesizer

4. **Full findings tables** (P0 through P3) unless `--summary` was set

5. **Auto-fix results** — what was fixed, what was skipped

6. **Coverage summary table** — per-document scorecard

7. **Recommendations**:
   - For systemic issues, suggest `/create-task` to track remediation
   - For large drift, suggest running `/doc-code-audit` on associated diagrams
   - For missing coverage, suggest running `/doc-rigor` to write new docs

---

## Domain Detail: Source Directories

The full mapping from domain scopes to source directories (for agent prompts).
All doc paths are relative to `docs/`. All source paths are relative to `crates/`.

```
coordination:
  docs: gossip-coordination/boundary-2-coordination.md,
        gossip-coordination/coordination-testing.md,
        gossip-coordination/simulation-harness.md,
        gossip-coordination/coordination-error-model.md
  source: gossip-contracts/src/coordination/,
          gossip-coordination/src/

etcd:
  docs: gossip-coordination/boundary-2-coordination.md (etcd sections)
  source: gossip-coordination-etcd/src/

persistence:
  docs: gossip-contracts/boundary-5-persistence.md,
        gossip-persistence-inmemory.md
  source: gossip-contracts/src/persistence/,
          gossip-persistence-inmemory/src/

identity:
  docs: gossip-contracts/boundary-1-identity-spine.md
  source: gossip-contracts/src/identity/

connectors:
  docs: gossip-connectors/boundary-4-connectors.md
  source: gossip-contracts/src/connector/,
          gossip-connectors/src/

shard-algebra:
  docs: gossip-contracts/boundary-3-shard-algebra.md,
        gossip-frontier/shard-algebra.md
  source: gossip-frontier/src/

scanning:
  docs: scanner-engine/,
        scanner-scheduler/,
        scanner-git/
  source: scanner-engine/src/,
          scanner-scheduler/src/,
          scanner-git/src/

findings:
  docs: gossip-contracts/boundary-5-persistence.md
  source: gossip-contracts/src/persistence/findings.rs

done-ledger:
  docs: gossip-contracts/boundary-5-persistence.md
  source: gossip-contracts/src/persistence/done_ledger.rs

overview:
  docs: architecture-overview.md
  source: (cross-cutting — check Cargo.toml deps, crate structure)
```

---

## Configuration

Default: 1 agent per 2-4 doc files + 1 synthesizer. Cap at 5 audit agents.

For `--full` mode with all 60+ docs, expect 5 audit agents (larger batches)
plus the synthesizer.

For domain-scoped mode, typically 1-2 audit agents + 1 synthesizer.

---

## Differentiation from Related Skills

| Skill | Target | Scope |
|-------|--------|-------|
| `/design-doc-audit` (this) | `docs/*.md` design documents | Architecture specs, boundary contracts, feature descriptions |
| `/doc-code-audit` | `diagrams/*.md` Mermaid files | Diagram node labels, edges, state machines vs code |
| `/doc-verify` | `*.rs` inline docstrings | `///` and `//!` comments within source files |
| `/doc-rigor` | `*.rs` inline docstrings | Write + verify code-level docs |

## Related Skills

- `/doc-code-audit` — Audit Mermaid diagrams against code (complementary to this skill)
- `/doc-rigor` — Write or improve inline code documentation
- `/doc-verify` — Verify inline docstring accuracy against code
- `/review-dispatch` — Full code review (not doc-focused)
- `/create-task` — Create tracked tasks for major remediation work
- `/execute-review-findings` — Implement fixes from audit findings
