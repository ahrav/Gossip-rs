---
name: doc-code-audit
description: Use when design docs in docs/ may be stale after code changes, when verifying diagrams match current types, or when checking that prose claims about invariants and APIs still hold. Audits documentation against code reality with incremental and full modes.
---

# Doc-Code Audit

A verify-first documentation consistency audit. Parallel specialist agents each
audit a subset of documentation files against the actual codebase, then a
synthesizer merges findings into a prioritized, actionable report.

**Core principle:** Treat every documentation claim as a hypothesis. Verify it
against the code before declaring it correct or incorrect.

## When to Use

- After significant code changes to verify docs still match reality
- Before merging a PR that touches both code and documentation
- When adding new diagrams or design docs to verify accuracy
- Periodic hygiene audits to catch doc drift
- After a PR where bot reviewers flagged doc inconsistencies
- When onboarding to a new area and wanting to trust the docs

## When NOT to Use

- For writing new documentation from scratch (use `/doc-rigor` instead)
- For reviewing code quality (use `/review-dispatch` instead)
- For checking doc style/prose quality (use `/code-doc-reviewer` instead)
- For verifying a single file's docs (use `/doc-verify` instead)

## Invocation

```text
/doc-code-audit [<scope>] [--flags]
```

### Positional Argument: Scope

The scope determines which docs and code are audited. If omitted, defaults to
`--incremental` mode (changes since last docs update).

**Domain scopes** (audit a specific boundary or feature area):

| Scope | Diagrams | Docs | Source Directories |
|-------|----------|------|--------------------|
| `coordination` | 05, 06, 07 | `docs/gossip-coordination/` | `crates/gossip-contracts/src/coordination/`, `crates/gossip-coordination/src/` |
| `etcd` | 20 | `docs/gossip-coordination/` | `crates/gossip-coordination-etcd/src/` |
| `persistence` | 08, 19 | `docs/gossip-contracts/boundary-5-persistence.md`, `docs/gossip-persistence-inmemory.md` | `crates/gossip-contracts/src/persistence/`, `crates/gossip-persistence-inmemory/src/` |
| `identity` | 02, 03 | `docs/gossip-contracts/boundary-1-identity-spine.md` | `crates/gossip-contracts/src/identity/` |
| `connectors` | 09, 14, 15, 16, 17, 18 | `docs/gossip-connectors/boundary-4-connectors.md` | `crates/gossip-contracts/src/connector/`, `crates/gossip-connectors/src/` |
| `shard-algebra` | 12, 13 | `docs/gossip-contracts/boundary-3-shard-algebra.md`, `docs/gossip-frontier/shard-algebra.md` | `crates/gossip-frontier/src/` |
| `scanning` | (none) | `docs/scanner-engine/`, `docs/scanner-scheduler/`, `docs/scanner-git/` | `crates/scanner-engine/src/`, `crates/scanner-scheduler/src/`, `crates/scanner-git/src/` |
| `findings` | 19 (section 2) | `docs/gossip-contracts/boundary-5-persistence.md` | `crates/gossip-contracts/src/persistence/findings.rs` |
| `done-ledger` | 19 (sections 3-4) | `docs/gossip-contracts/boundary-5-persistence.md` | `crates/gossip-contracts/src/persistence/done_ledger.rs` |
| `overview` | 00, 01, 04, 10, 11 | `docs/architecture-overview.md` | (cross-cutting) |

**File paths** — audit specific files directly:

```text
/doc-code-audit diagrams/19-persistence-contracts.md diagrams/20-etcd-coordinator-persistence.md
/doc-code-audit docs/gossip-coordination/boundary-2-coordination.md
```

### Flags

| Flag | Effect |
|------|--------|
| `--incremental` | **(Default)** Audit only docs in scope of code changed since last docs update. Uses `git log` to find recently modified `.rs` files, maps them to docs via `docs/scope-map.toml`, and audits those docs. |
| `--full` | Comprehensive audit of ALL docs and diagrams against the entire codebase. Expensive but thorough. |
| `--diagrams-only` | Restrict audit to `diagrams/` files (skip `docs/`). |
| `--docs-only` | Restrict audit to `docs/` files (skip `diagrams/`). |
| `--strict` | Treat all STALE findings as errors (not warnings). Useful for pre-merge gates. |
| `--skip-mermaid` | Skip Mermaid diagram structural verification (only check prose claims). |

---

## Phase 0 — Scope Resolution (Orchestrator)

Determine which documents and source files to audit.

### Incremental Mode (default)

1. Find the merge-base with the target branch (or the last commit that touched
   any file in `diagrams/` or `docs/` as fallback):
   ```bash
   git merge-base main HEAD 2>/dev/null || git log -1 --format='%H' -- diagrams/ docs/
   ```

2. Find all `.rs` files changed since the merge-base:
   ```bash
   git diff --name-only <merge-base>..HEAD -- '*.rs'
   ```

3. Read `docs/scope-map.toml` and map each changed `.rs` file to its in-scope
   docs. Also check if any changed `.rs` file falls under a diagram's source
   material (see `diagrams/00-README.md` Source Material table).

4. Deduplicate the doc list. These are the files to audit.

5. If no docs are in scope (all code changes are in undocumented directories),
   report "No docs in scope of recent code changes" and stop.

### Full Mode

1. Collect all files in `diagrams/` (including `00-README.md`).
2. Collect all `.md` files in `docs/` and its subdirectories (excluding
   `findings/`, `assets/`, and `README.md`).
3. These are all the files to audit.

### Domain-Scoped Mode

Use the domain-to-file mapping table above. Collect the listed diagrams and
docs for the specified domain.

### File-Path Mode

Use the explicitly provided file paths.

---

## Phase 1 — Parallel Audit Agents

Partition the collected doc files into batches of 2-3 files per agent (to keep
context focused). Launch all agents **in a single message** using the Task tool
with `subagent_type=general`.

### Agent Prompt Template

Each agent receives this prompt with `{DOC_FILES}`, `{SOURCE_DIRS}`, and
`{AUDIT_TYPE}` filled in:

```text
You are a documentation-vs-code consistency auditor. Your job is to read each
documentation file, extract every verifiable claim, and check it against the
actual codebase. You are skeptical by default — assume nothing is correct
until verified.

## Documents to Audit

{DOC_FILES}

## Source Directories to Check Against

{SOURCE_DIRS}

## Audit Type: {AUDIT_TYPE}

If "incremental": Focus on claims related to recently changed code. The following
.rs files changed since the last docs update:
{CHANGED_RS_FILES}

If "full": Check every verifiable claim in the document.

## What to Verify

For each document, systematically extract and verify:

### 1. Type & Struct Claims
- Do named types (structs, enums, traits) exist in code?
- Are field lists accurate? (field names, types, visibility)
- Are variant lists accurate for enums?
- Are generic parameters correct?

### 2. Function & Method Claims
- Do named functions/methods exist?
- Are signatures accurate? (parameters, return types, trait bounds)
- Are the described behaviors correct? (read the actual implementation)
- Do documented error conditions match the code?

### 3. Invariant & Contract Claims
- Are stated invariants enforced in code? (look for assertions, type-system
  enforcement, constructor validation)
- Do "must always" / "must never" claims hold?
- Are documented preconditions checked?

### 4. State Machine & Lifecycle Claims
- Do documented states match enum variants or state fields?
- Are documented transitions the only ones possible in code?
- Are any code transitions missing from the diagram?
- Are any diagram transitions impossible in code?

### 5. Dependency & Architecture Claims
- Do "depends on" / "imports from" claims match Cargo.toml and use statements?
- Are crate-to-boundary mappings accurate?
- Are build tier / compilation order claims correct?

### 6. Mermaid Diagram Accuracy (unless --skip-mermaid)
- Do node labels match actual type/function names?
- Do edges represent real relationships in code?
- Is the tree/graph structure consistent with the prose in the same file?
- Do subgraph groupings match actual module/crate boundaries?

### 7. Cross-Reference Accuracy
- Do links to other docs/diagrams point to files that exist?
- Are cross-referenced claims consistent between documents?
- Do "source code references" tables list files that exist with accurate descriptions?

## How to Verify

Use these tools to check claims against code:

- `colgrep "<semantic query>" --include="*.rs" <source_dir>` — semantic code search
- `colgrep -e "<exact_name>" --include="*.rs" <source_dir>` — exact name search
- Read specific files when you need to verify function bodies, struct fields, or invariant enforcement
- Use Glob to find files when a doc references a file that may have moved

IMPORTANT: Actually read and understand the relevant code. Do not guess or
assume based on names alone. A function named `validate_foo` might not actually
validate foo.

## Classification

For each finding, classify it as:

| Category | Meaning | Severity |
|----------|---------|----------|
| INCORRECT | Doc states something that is demonstrably wrong | HIGH |
| STALE | Doc references something that was renamed, moved, or removed | HIGH |
| INCONSISTENT | Doc contradicts itself or another doc in the same set | MEDIUM |
| INCOMPLETE | Doc omits something that exists in code and should be documented | MEDIUM |
| ASPIRATIONAL | Doc describes target behavior that is not yet implemented | LOW |
| UNVERIFIABLE | Claim cannot be checked (e.g., performance assertion without benchmark) | INFO |

## Output Format

Return a markdown document:

```markdown
# Audit: {document_filename}

## Summary
- Claims checked: N
- Findings: X (Y high, Z medium, W low)
- Verdict: CONSISTENT / DRIFT DETECTED / MAJOR INCONSISTENCIES

## Findings

| # | Category | Severity | Doc Line | Claim | Code Reality | File:Line |
|---|----------|----------|----------|-------|-------------|-----------|
| 1 | STALE | HIGH | L42 | "Function `foo` returns `Bar`" | `foo` was renamed to `foo_into`, returns `Baz` | src/lib.rs:128 |
| 2 | INCORRECT | HIGH | L105 | "ShardState has 4 variants" | ShardState has 5 variants (Split was added) | types.rs:67 |

## Details

### Finding 1: {title}
- **Doc says**: {quote from doc}
- **Code says**: {what the code actually does, with file:line}
- **Evidence**: {how you verified — what you searched, what you read}
- **Suggested fix**: {how to update the doc}

## Verified Claims (sample)

To demonstrate thoroughness, list 5-10 claims that were checked and found correct:

| Claim | Verified Against |
|-------|-----------------|
| "TenantId is a 32-byte BLAKE3 hash" | identity/types.rs:15 — `define_id_32!(TenantId, ...)` |
```

## Rules

- NEVER report a finding without verifying it against actual code first.
- If you cannot find the relevant code, say so explicitly — do not guess.
- Quote exact doc text and exact code for every finding.
- Distinguish between "the doc is wrong" and "the doc is ambiguous."
- If a doc describes target/aspirational behavior, classify it as ASPIRATIONAL
  only if the doc itself says so. If the doc presents aspirational behavior as
  current fact, classify as INCORRECT.
- Check source-code reference tables: do listed files exist? Are descriptions
  accurate?
```

---

## Phase 2 — Synthesize & Prioritize (Single Agent)

After all audit agents complete, launch **1 synthesizer agent** using the Task
tool with `subagent_type=general`.

### Synthesizer Prompt

```text
You are the Documentation Audit Synthesizer. Multiple audit agents have
independently reviewed documentation files against the codebase. Your job is
to merge their findings into one actionable report.

## Agent Reports

{ALL_AGENT_REPORTS}

## Your Task

### 1. Deduplicate

If multiple agents flagged the same underlying issue (e.g., a renamed function
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

### 4. Output Format

```markdown
## Doc-Code Audit Report

**Mode**: {incremental|full|domain:<name>|files}
**Documents audited**: N
**Total findings**: X (P0: A, P1: B, P2: C, P3: D)
**Overall verdict**: CONSISTENT / DRIFT DETECTED / MAJOR INCONSISTENCIES

### Executive Summary

{2-3 sentence overview of the audit results. What areas are clean? Where is
the most drift?}

### P0 — Must Fix (doc could cause bugs)

| # | Document | Line | Finding | Code Reality |
|---|----------|------|---------|-------------|

{Detailed write-ups for each P0 finding with exact doc text, exact code
references, and suggested fix}

### P1 — Should Fix (stale references)

| # | Document | Line | Finding | Code Reality |
|---|----------|------|---------|-------------|

### P2 — Consider (inconsistencies)

{Table only unless context is needed}

### P3 — Low Priority

{Table only}

### Clean Documents

The following documents passed audit with no findings:
- {list of clean docs}

### Coverage Summary

| Document | Claims Checked | Findings | Verdict |
|----------|---------------|----------|---------|
| `diagrams/19-persistence-contracts.md` | 47 | 3 | DRIFT DETECTED |
| `diagrams/20-etcd-coordinator-persistence.md` | 31 | 0 | CONSISTENT |

### Recommendations

{If patterns emerge — e.g., "all connector docs are stale after the
enumerate_page refactor" — call them out as systemic issues}
```

### Rules

- Present findings directly. Do not soften or filter them.
- If all docs are consistent, say so clearly — a clean audit is valuable info.
- Preserve file:line citations from the agent reports.
- Do NOT add your own findings — you are a synthesizer, not an auditor.
- If an agent's finding seems wrong (they misread the code), note it as
  "disputed" with your reasoning, but still include it.
```

---

## Phase 3 — Presentation

After the synthesizer completes, present the report directly to the user.

If there are P0 findings, call them out prominently at the top of your message.

If the user wants fixes applied, offer to:
1. Fix each confirmed finding in the docs (using the Edit tool)
2. Run the verification again to confirm the fixes are correct

---

## Domain Detail: Source Directories

The full mapping from domain scopes to source directories (for agent prompts):

```yaml
coordination:
  diagrams: 05-shard-and-run-state-machines.md, 06-fencing-protocol.md, 07-lease-lifecycle.md
  docs: docs/gossip-coordination/boundary-2-coordination.md, docs/gossip-coordination/coordination-testing.md, docs/gossip-coordination/simulation-harness.md
  source: crates/gossip-contracts/src/coordination/, crates/gossip-coordination/src/

etcd:
  diagrams: 20-etcd-coordinator-persistence.md
  docs: docs/gossip-coordination/boundary-2-coordination.md (etcd sections)
  source: crates/gossip-coordination-etcd/src/

persistence:
  diagrams: 08-pagecommit-typestate.md, 19-persistence-contracts.md
  docs: docs/gossip-contracts/boundary-5-persistence.md, docs/gossip-persistence-inmemory.md
  source: crates/gossip-contracts/src/persistence/, crates/gossip-persistence-inmemory/src/

identity:
  diagrams: 02-boundary-dependency-graph.md, 03-id-derivation-dag.md
  docs: docs/gossip-contracts/boundary-1-identity-spine.md
  source: crates/gossip-contracts/src/identity/

connectors:
  diagrams: 09-circuit-breaker.md, 14-connector-architecture.md, 16-cursor-resume-strategy.md, 17-filesystem-walk-state-machine.md, 18-streaming-split-estimation.md
  docs: docs/gossip-connectors/boundary-4-connectors.md
  source: crates/gossip-contracts/src/connector/, crates/gossip-connectors/src/

shard-algebra:
  diagrams: 12-split-operations.md, 13-shard-algebra-types.md
  docs: docs/gossip-contracts/boundary-3-shard-algebra.md, docs/gossip-frontier/shard-algebra.md
  source: crates/gossip-frontier/src/

scanning:
  diagrams: (none specific)
  docs: docs/scanner-engine/, docs/scanner-scheduler/, docs/scanner-git/
  source: crates/scanner-engine/src/, crates/scanner-scheduler/src/, crates/scanner-git/src/

findings:
  diagrams: 19-persistence-contracts.md (section 2 only)
  docs: docs/gossip-contracts/boundary-5-persistence.md
  source: crates/gossip-contracts/src/persistence/findings.rs

done-ledger:
  diagrams: 19-persistence-contracts.md (sections 3-4 only)
  docs: docs/gossip-contracts/boundary-5-persistence.md
  source: crates/gossip-contracts/src/persistence/done_ledger.rs

overview:
  diagrams: 00-README.md, 01-system-overview.md, 04-end-to-end-scan-flow.md, 10-failure-modes-and-recovery.md, 11-tenant-isolation.md
  docs: docs/architecture-overview.md
  source: (cross-cutting — check Cargo.toml deps, crate structure)
```

## Configuration

Default: 1 agent per 2-3 doc files + 1 synthesizer.

For `--full` mode with all 20+ diagrams and 30+ docs, expect 15-20 agents plus
the synthesizer.

For domain-scoped mode, typically 1-3 audit agents + 1 synthesizer.

## Related Skills

- `/doc-rigor` — Write or improve documentation (this skill checks existing docs)
- `/doc-verify` — Verify a single file's docs against code
- `/review-dispatch` — Full code review (not doc-focused)
- `/doc-rigor-verify` — Write docs then verify them (pipeline, not audit)
- `/pr-comment-response` — Address specific review comments on a PR
