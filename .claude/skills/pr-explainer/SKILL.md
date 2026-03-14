---
name: pr-explainer
description: Explain a PR's purpose, motivation, and architectural context with ASCII diagrams. Use when the user wants to understand what a PR does, why it exists, how it fits into the system, or asks for a visual summary of changes. Triggers on "explain this PR", "what does this PR do", "summarize this branch", "show me what changed", or `/pr-explainer`.
---

# PR Explainer

## Overview

Produce a big-picture-first explanation of a PR (or current branch diff) grounded
in the project's design docs and architecture diagrams. Output is structured
top-down: motivation first, architecture context second, details last.

All diagrams use **ASCII box-and-arrow art** so they render correctly in any
terminal. Do NOT use Mermaid — the primary consumer is the CLI, not GitHub.

## Input Detection

1. **Argument is a PR number or URL** → use `gh pr view <arg> --json title,body,baseRefName` and `gh pr diff <arg>`
2. **No argument** → diff the current branch against `main`:
   - `git log main..HEAD --oneline` for commit history
   - `git diff main...HEAD` for the full diff
   - `git diff main...HEAD --stat` for a file summary

## Workflow

### Step 1: Gather the Diff

Collect the raw material:

```bash
# For current branch (no argument):
git diff main...HEAD --stat          # file-level summary
git diff main...HEAD                 # full diff
git log main..HEAD --oneline         # commit history

# For a PR number:
gh pr view <number> --json title,body,baseRefName,headRefName
gh pr diff <number>
```

### Step 2: Identify Affected Boundaries

Read `docs/scope-map.toml` to find which design docs cover the changed files.
For each changed file path, match against `[[scopes]]` entries to find
the relevant `doc` paths.

Then read:
- The matched design doc(s) — to understand the architectural context
- `diagrams/00-README.md` — to find relevant existing Mermaid diagrams
- Any specific diagram files that cover the affected boundaries

### Step 3: Produce the Explanation

Follow the output template in `references/output-template.md`. Key rules:

- **Top-down**: Start with "why", end with file details
- **Two diagrams minimum**:
  1. **Architecture context** — where the change sits in the system (highlight affected components)
  2. **Change flow** — what the change does (data flow, state transitions, or structural changes)
- **ASCII diagrams only** — must render in a monospace terminal
- **Ground claims in design docs** — reference specific docs/diagrams when explaining context
- **Be concise** — the "Why" section should be 1-3 sentences, not paragraphs

### Step 4: Diagram Guidelines

All diagrams are ASCII box-and-arrow art inside fenced code blocks. Rules:

- Use box-drawing characters (`┌─┐│└─┘`) or simple ASCII (`+--+|`) for boxes
- Use arrows: `──▶`, `───`, `---->`, `- - ->` (dashed for optional/test paths)
- Mark changed components with `[*]` prefix or `(changed)` suffix
- Mark new components with `[+]` prefix or `(new)` suffix
- Keep diagrams 80 columns wide max so they don't wrap
- Keep diagrams focused — 5-10 nodes max, not the entire system
- Reference existing diagrams from `diagrams/` when the change modifies a documented flow

Example architecture diagram:

```
  B5: Persistence
  ┌─────────────────────────────────────────────┐
  │                                             │
  │  ┌──────────────┐    ┌──────────────────┐   │
  │  │ DoneLedger   │    │ FindingsSink     │   │
  │  │ trait        │    │ trait            │   │
  │  └──────┬───────┘    └────────┬─────────┘   │
  │         │                     │             │
  │  ┌──────▼───────┐    ┌───────▼──────────┐   │
  │  │ InMemory  [*]│    │ Postgres      [*]│   │
  │  │ (changed)    │    │ (changed)        │   │
  │  └──────────────┘    └──────────────────┘   │
  │                                             │
  │  ┌──────────────────┐                       │
  │  │ Lattice Tests [+]│                       │
  │  │ (new)            │                       │
  │  └──────────────────┘                       │
  └─────────────────────────────────────────────┘

  [*] = changed   [+] = new
```

Example flow diagram:

```
  Old merge:                    New merge:
  (rank, finished, started)     (rank, finished, started,
                                 fence_epoch, run_id,
                                 shard_id, error_code)

  3-field tie-break ──────▶ 7-field tie-break
       ambiguous                 deterministic,
                                 matches Postgres
```

### Complex Diagrams

For particularly complex architecture or flow diagrams, invoke the `/ascii-diagrams`
skill which has deeper guidance on box-drawing conventions, alignment, and
multi-layer layouts.

## Anti-Patterns

- Do NOT use Mermaid — output must be readable in a terminal
- Do NOT dump the raw diff — that's what `git diff` is for
- Do NOT list every changed line — focus on what matters architecturally
- Do NOT invent motivation — derive it from the diff, commit messages, and PR description
- Do NOT skip the diagrams — they are the primary value of this skill
- Do NOT create diagrams that show the entire system — zoom in on what changed
