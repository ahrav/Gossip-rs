---
name: guide-sync
description: Synchronize the external learning guide at /Users/ahrav/Projects/gossip-rs-learning-guide
  with the current state of the Gossip-rs codebase. Detects removed types, renamed
  APIs, deleted modules, stale code examples, wrong chapter cross-references, and
  obsolete architecture descriptions. Produces a prioritized diff report and applies
  fixes.
user-invocable: true
---

# Guide Sync

Audit and update the external learning guide to match the current codebase.
Parallel exploration agents compare every guide section against the live source
code, then a synthesizer produces a prioritized remediation plan that the
orchestrator executes.

**Core principle:** The guide must describe the code that exists today, not the
code that existed when the chapter was written. Every type name, method
signature, module path, and architecture claim is verified against the current
codebase before the guide is updated.

## Paths

| Asset | Location |
|-------|----------|
| Learning guide | `/Users/ahrav/Projects/gossip-rs-learning-guide` |
| Codebase | `/Users/ahrav/Projects/Gossip-rs` |

## When to Use

- After removing, renaming, or restructuring code (types, traits, modules, crates)
- After a major refactor that changes public API surfaces
- After adding new crates or removing existing ones
- Periodic hygiene sync to catch guide drift
- Before publishing or sharing the guide externally

## When NOT to Use

- For auditing in-tree design docs in `docs/` (use `/design-doc-audit`)
- For auditing Mermaid diagrams in `diagrams/` (use `/doc-code-audit`)
- For writing new guide chapters from scratch (manual authoring)
- For improving inline code docstrings (use `/doc-rigor`)

## Invocation

```
/guide-sync [<scope>] [--flags]
```

### Positional Argument: Scope

The scope determines which guide sections and crate directories are compared.
If omitted, defaults to `--full` (all sections).

**Section scopes** (audit a specific guide section):

| Scope | Guide Directory | Primary Crates |
|-------|----------------|----------------|
| `prologue` | `00-prologue/` | (cross-cutting) |
| `foundations` | `01-foundations/` | `gossip-contracts/src/identity/` |
| `identity` | `02-boundary-1-identity-spine/` | `gossip-contracts/src/identity/` |
| `theory` | `03-distributed-systems-theory/` | (conceptual, light code refs) |
| `coordination` | `04-boundary-2-coordination/` | `gossip-contracts/src/coordination/`, `gossip-coordination/src/`, `gossip-coordination-etcd/src/` |
| `shard-algebra` | `05-boundary-3-shard-algebra/` | `gossip-frontier/src/` |
| `connector` | `06-boundary-4-connector/` | `gossip-contracts/src/connector/`, `gossip-connectors/src/`, `gossip-scanner-runtime/src/` |
| `persistence` | `07-boundary-5-persistence/` | `gossip-contracts/src/persistence/`, `gossip-persistence-inmemory/src/` |
| `cross-cutting` | `08-cross-cutting/` | (cross-cutting) |
| `appendices` | `09-appendices/` | (cross-cutting) |
| `scanner-engine` | `10-scanner-engine/` | `scanner-engine/src/` |
| `scan-driver` | `11-scan-driver-and-pipeline/` | `gossip-scanner-runtime/src/`, `scanner-scheduler/src/`, `scanner-git/src/` |
| `scanner-git` | `12-scanner-git/` | `scanner-git/src/` |
| `scheduler` | `13-scanner-scheduler/` | `scanner-scheduler/src/` |
| `runtime` | `14-scanner-runtime-and-worker/` | `gossip-scanner-runtime/src/`, `gossip-worker/src/` |

### Flags

| Flag | Default | Effect |
|------|---------|--------|
| `--full` | on | Audit all guide sections against the full codebase |
| `--report-only` | off | Produce the diff report but do not apply fixes |
| `--delete-obsolete` | off | Delete chapters whose entire subject was removed (prompts for confirmation) |
| `--renumber` | off | Renumber chapters after deletions to close numbering gaps |
| `--strict` | off | Treat all findings as errors (useful for CI-like checks) |

---

## Phase 0 -- Codebase Snapshot (Orchestrator)

Build a current-state inventory of the codebase to compare against.

1. **List all crates** under `crates/` with their source files:
   ```bash
   ls /Users/ahrav/Projects/Gossip-rs/crates/
   ```

2. **For each crate**, collect public types, traits, and functions:
   - Use `colgrep -e "pub (fn|struct|enum|trait|type|mod)" --include="*.rs"` per crate
   - Record which crates exist and which have been removed

3. **Check for removed concepts** that guides commonly reference:
   - Search for specific types/traits the guide references but that no longer
     exist (e.g., `EnumerationPage`, `PageValidationError`, `ConnectorConformance`)
   - Search for removed methods (e.g., `enumerate_page`, `enumerate_page_bounds`)
   - Search for removed modules (e.g., `page_validator`, `conformance`)

4. **Build a removal manifest**: a list of `(concept, was_in, status)` tuples
   where status is `removed`, `renamed:<new_name>`, or `moved:<new_location>`.

---

## Phase 1 -- Parallel Guide Audit (up to 5 agents)

Partition the guide sections into batches of 2-3 sections per agent. Launch all
agents **in a single message** using the Task tool with `subagent_type=general`.

### Agent Prompt Template

Each agent receives this prompt with `{GUIDE_SECTIONS}`, `{CRATE_DIRS}`, and
`{REMOVAL_MANIFEST}` filled in:

```
You are a learning-guide-vs-codebase consistency auditor. Your job is to read
each guide chapter, extract every verifiable claim, and check it against the
actual codebase at /Users/ahrav/Projects/Gossip-rs.

## Guide Sections to Audit

{GUIDE_SECTIONS}

## Crate Directories to Check Against

{CRATE_DIRS}

## Known Removals / Renames

The following concepts have been removed or renamed since the guide was last
updated. Flag every guide reference to these:

{REMOVAL_MANIFEST}

## What to Check

For each guide chapter, systematically verify:

### 1. Type, Struct, Enum, Trait References
- Does every named type still exist in the codebase?
- Are struct field lists accurate (names, types, count)?
- Are enum variant lists accurate?
- Are trait method signatures accurate?

### 2. Method and Function References
- Does every named method still exist on the type the guide says it does?
- Are method signatures (parameters, return types) accurate?
- Are described behaviors still correct?

### 3. Code Blocks
- Does every inline code block match the current source?
- Are file:line references still accurate?
- Do code comments in examples match the current code comments?

### 4. Module and Crate Structure
- Does the guide's module layout match the current `mod.rs` / `lib.rs`?
- Are "N files" counts accurate?
- Do listed source files still exist?
- Are there new files the guide does not mention?

### 5. Architecture and Data Flow Claims
- Are dependency direction claims still correct?
- Do described data flow paths match the current call graph?
- Are layer/tier descriptions accurate?

### 6. Chapter Cross-References
- Do "Chapter N" references point to the correct content after renumbering?
- Do forward/backward references between chapters still make sense?

### 7. README and Appendix Accuracy
- Does the README project status table match reality?
- Does the glossary reference only types that exist?
- Does the source file map list only files that exist?

## How to Verify

- Use `colgrep` for semantic and exact code search
- Read specific source files to verify method signatures and struct fields
- Use Glob to find files when a guide references a file that may have moved
- Use Grep for exact identifier lookups

IMPORTANT: Actually read the code. Do not guess based on names.

## Classification

| Category | Meaning | Severity |
|----------|---------|----------|
| REMOVED | Guide references a type/method/module that no longer exists | HIGH |
| RENAMED | Guide uses an old name; the concept still exists under a new name | HIGH |
| STALE_CODE | Inline code block does not match current source | HIGH |
| WRONG_SIGNATURE | Method/function signature in guide differs from code | HIGH |
| WRONG_STRUCTURE | Module layout, file counts, or crate structure is wrong | MEDIUM |
| STALE_XREF | Chapter cross-reference points to wrong content | MEDIUM |
| INCOMPLETE | Guide omits significant new functionality | LOW |
| ASPIRATIONAL | Guide describes behavior not yet implemented | LOW |

## Output Format

Return a markdown document with:

# Audit: {section_name}

## Summary
- Chapters audited: N
- Findings: X (Y high, Z medium, W low)
- Chapters with no findings: [list]
- Chapters that may need deletion: [list, if entire subject was removed]

## Findings

| # | Category | Severity | File | Line | Claim | Reality | Code Ref |
|---|----------|----------|------|------|-------|---------|----------|

## Details

### Finding N: {title}
- **Guide says**: {quote}
- **Code says**: {current state, with file:line}
- **Suggested fix**: {specific edit or "delete chapter"}

## Obsolete Chapters
List any chapters whose entire subject has been removed from the codebase.
```

---

## Phase 2 -- Synthesize & Plan (Single Agent)

After all audit agents complete, launch **1 synthesizer agent** using the Task
tool with `subagent_type=general`.

### Synthesizer Prompt

```
You are the Guide Sync Synthesizer. Multiple audit agents have independently
compared learning guide sections against the Gossip-rs codebase. Merge their
findings into one actionable remediation plan.

## Agent Reports

{ALL_AGENT_REPORTS}

## Your Task

### 1. Deduplicate
Group identical findings (same removed type referenced in multiple chapters).

### 2. Prioritize
- **P0 -- DELETE**: Entire chapters about removed features (e.g., page validation
  chapter when page validation was removed)
- **P1 -- REWRITE**: Sections with fundamentally wrong architecture descriptions
  (e.g., "five-method convention" when only four methods remain)
- **P2 -- EDIT**: Specific lines with wrong type names, signatures, or counts
- **P3 -- XREF**: Chapter cross-reference numbering fixes after deletions
- **P4 -- LOW**: Minor omissions, aspirational content

### 3. Build Remediation Plan
For each finding, specify the exact action:
- `DELETE file` -- Remove an obsolete chapter file
- `REWRITE section` -- Replace a section with updated content
- `EDIT line` -- Fix a specific line (old text -> new text)
- `RENAME file` -- Renumber a chapter file
- `UPDATE_README` -- Update README.md tables and stats

### 4. Output Format

## Guide Sync Remediation Plan

**Sections audited**: N
**Total findings**: X (P0: A, P1: B, P2: C, P3: D, P4: E)
**Chapters to delete**: [list]
**Chapters to rewrite**: [list]
**Line edits**: N

### Actions (ordered by priority)

| # | Priority | Action | File | Details |
|---|----------|--------|------|---------|
| 1 | P0 | DELETE | 06-boundary-4-connector/04-page-validation.md | Page validation removed |
| 2 | P1 | REWRITE | 06-boundary-4-connector/03-enumeration-and-read-traits.md | Remove enumerate_page |
| 3 | P2 | EDIT | 06-boundary-4-connector/01-connector-problem-space.md:48 | "EnumerationPage" -> remove |

### Systemic Patterns
{Common drift patterns across multiple chapters}

### Post-Fix Actions
- Renumber chapters in affected sections
- Update README.md status table, reading path, topic jump table
- Update glossary (remove deleted terms, fix renamed terms)
- Update source file map (remove deleted files, fix paths)
```

---

## Phase 3 -- Execute Remediation (Orchestrator)

Work through the synthesizer's remediation plan in priority order.

### Step 1: Confirm Deletions (P0)

If `--delete-obsolete` was set:
- Delete each obsolete chapter file
- Otherwise, ask the user for confirmation before deleting

### Step 2: Rewrite Sections (P1)

For each section requiring rewrite:
1. Read the current guide chapter
2. Read the current codebase source files for that section
3. Rewrite the section to match the current code
4. Preserve the guide's pedagogical style and narrative flow

### Step 3: Apply Line Edits (P2)

For each line edit:
1. Read the guide file
2. Apply the specific edit using the Edit tool
3. Verify the edit is consistent with surrounding text

### Step 4: Fix Cross-References (P3)

After deletions and renumbering:
1. Renumber chapter files to close gaps (if `--renumber` is set)
2. Search all guide files for "Chapter N" references
3. Update each reference to point to the correct content

### Step 5: Update Meta Files

1. **README.md**: Update project status table, sequential reading path, topic
   jump table, and documentation stats
2. **Glossary** (`09-appendices/D-glossary.md`): Remove entries for deleted
   types, update entries for renamed types
3. **Source File Map** (`09-appendices/E-source-file-map.md`): Remove entries
   for deleted files, update chapter-to-file mappings
4. **REFERENCES.md**: Remove references only cited by deleted chapters (if any)

### Step 6: Verify (if not --report-only)

After all edits, run a targeted search for any remaining stale references:
```bash
# Search for known-removed identifiers across the guide
grep -r "EnumerationPage\|enumerate_page\|page_validator" /Users/ahrav/Projects/gossip-rs-learning-guide/ --include="*.md"
```

Report any remaining issues to the user.

---

## Guide Section to Crate Mapping

The full mapping from guide sections to primary source directories. All crate
paths are relative to `/Users/ahrav/Projects/Gossip-rs/crates/`.

```yaml
00-prologue:
  crates: (cross-cutting -- Cargo.toml, crate list)

01-foundations:
  crates: gossip-contracts/src/identity/

02-boundary-1-identity-spine:
  crates: gossip-contracts/src/identity/

03-distributed-systems-theory:
  crates: (conceptual -- light code references to coordination/)

04-boundary-2-coordination:
  crates: gossip-contracts/src/coordination/
          gossip-coordination/src/
          gossip-coordination-etcd/src/

05-boundary-3-shard-algebra:
  crates: gossip-frontier/src/

06-boundary-4-connector:
  crates: gossip-contracts/src/connector/
          gossip-connectors/src/
          gossip-scanner-runtime/src/

07-boundary-5-persistence:
  crates: gossip-contracts/src/persistence/
          gossip-persistence-inmemory/src/

08-cross-cutting:
  crates: (cross-cutting -- references all boundaries)

09-appendices:
  crates: (cross-cutting -- glossary, source map, TLA+)

10-scanner-engine:
  crates: scanner-engine/src/

11-scan-driver-and-pipeline:
  crates: gossip-scanner-runtime/src/
          scanner-scheduler/src/
          scanner-git/src/

12-scanner-git:
  crates: scanner-git/src/

13-scanner-scheduler:
  crates: scanner-scheduler/src/

14-scanner-runtime-and-worker:
  crates: gossip-scanner-runtime/src/
          gossip-worker/src/
          scanner-rs-cli/src/
```

---

## Configuration

Default: 3-5 audit agents (one per 2-3 guide sections) + 1 synthesizer.

For single-section scope, typically 1 audit agent + 1 synthesizer.

For `--full` mode across all 15 sections, use 5 agents with 3 sections each.

---

## Remediation Style Guide

When rewriting guide sections:

- **Preserve narrative voice.** The guide uses a first-principles pedagogical
  style with opening failure scenarios, "why" explanations, and progressive
  disclosure. Match this when rewriting.
- **Update code blocks to match current source.** Copy the actual code; do not
  paraphrase or approximate.
- **Remove, do not stub.** When a feature is removed, delete the section rather
  than leaving a "this was removed" note. The guide should describe what exists.
- **Fix forward references.** After deleting or renumbering chapters, every
  "Chapter N" reference in the guide must be updated.
- **Keep the toxic-byte principle.** Never include raw secrets, credentials, or
  path information in guide examples. Follow the redaction conventions.

---

## Related Skills

- `/design-doc-audit` -- Audit in-tree design docs in `docs/` (not the external guide)
- `/doc-code-audit` -- Audit Mermaid diagrams in `diagrams/` against code
- `/doc-rigor` -- Write or improve inline code documentation
- `/doc-verify` -- Verify inline docstring accuracy against code
- `/create-task` -- Create tracked tasks for major remediation work
