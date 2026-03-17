---
name: pr-explainer
description: Explain a PR's purpose, motivation, and architectural context with ASCII diagrams. Use when the user wants to understand what a PR does, why it exists, how it fits into the system, or asks for a visual summary of changes. Triggers on "explain this PR", "what does this PR do", "summarize this branch", "show me what changed", or `/pr-explainer`.
---

# PR Explainer

## Overview

Produce a first-principles explanation of a PR (or current branch diff) that
builds understanding incrementally. A reader who has never seen the codebase
should be able to follow the explanation and understand not just *what*
changed, but *why each piece exists* and *how the pieces interact*.

Output is structured top-down: problem first, then mechanism, then details.
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

### Step 3: Understand the Mechanism Deeply

Before writing, you must be able to answer these questions about the change:

1. **What problem does it solve?** Not just "adds feature X" but "without X,
   the system cannot do Y because Z."
2. **What are the moving pieces?** Every new type, trait, function, or
   structural change should have a sentence explaining its role.
3. **Why does each piece exist?** If something was split into two parts,
   why couldn't it be one? If something runs concurrently, what would happen
   if it ran sequentially?
4. **How do the pieces connect?** What data flows between components? What
   ordering constraints exist? Where are the synchronization boundaries?
5. **What constraints shaped the design?** Backpressure, ordering
   requirements, failure handling, performance, API compatibility.

If you cannot answer these questions from the diff alone, read the referenced
source files and design docs until you can.

### Step 4: Produce the Explanation

Follow the output template in `references/output-template.md`. The core
principle is **incremental understanding**:

1. **The Problem** — what's broken or missing, stated concretely
2. **The Approach** — the high-level solution shape, in one paragraph
3. **Architecture Context** — where this fits in the existing system
4. **How It Works** — walk through the mechanism step by step, introducing
   each component with its purpose *before* showing it in a diagram
5. **Key Decisions** — non-obvious trade-offs and constraints
6. **Detailed Changes** — file-by-file index for reference

### Step 5: Diagram Rules

#### Foundational rule

**Every named box, arrow, and annotation in a diagram must be explained in
the surrounding prose.** If a diagram shows "Sender" and "Drainer", the text
must explain what each one does, what data it handles, and why it exists as
a separate thing. A diagram that contains unexplained components is worse
than no diagram — it creates the illusion of understanding.

#### Visual conventions

- Use box-drawing characters (`┌─┐│└─┘`) or simple ASCII (`+--+|`) for boxes
- Use arrows: `──▶`, `───`, `---->`, `- - ->` (dashed for optional/test paths)
- Mark changed components with `[*]` prefix or `(changed)` suffix
- Mark new components with `[+]` prefix or `(new)` suffix
- Keep diagrams 80 columns wide max so they don't wrap
- Keep diagrams focused — 5-10 nodes max, not the entire system
- Reference existing diagrams from `diagrams/` when the change modifies a
  documented flow

#### Labeling requirements

- **Arrows must be labeled** with what flows through them (data type, message
  kind, or semantic role). Unlabeled arrows are ambiguous.
- **Boundaries must be marked.** If components run on different threads,
  different processes, or different sides of a channel, draw a boundary line
  and label it (e.g., `── channel ──`, `── thread boundary ──`).
- **Concurrency must be visible.** When things run in parallel, use side-by-
  side layout or explicit annotations like `(concurrent)`, `Thread 1 / Thread 2`.
  The reader must see *where* parallelism happens and *what synchronizes* the
  parallel paths.

#### Diagram types (minimum two)

1. **Architecture context diagram** — where the change sits in the existing
   system. Show the boundary, the components within it, and highlight which
   ones are new or changed. This orients the reader.
2. **Mechanism diagram** — how the change works internally. This is the
   diagram that shows data flow, concurrency, channels, state transitions,
   or structural relationships. This is where the explanation lives.

For complex mechanisms, use multiple focused diagrams rather than one dense
diagram. Each diagram should make exactly one point clear.

#### Before/after diagrams

When a change modifies existing behavior (not just adding new behavior),
include a before/after comparison that makes the structural difference
visible. Show what the system did before, what it does now, and label the
key difference.

#### Complex diagrams

For particularly complex architecture or flow diagrams, invoke the
`/ascii-diagrams` skill which has deeper guidance on box-drawing conventions,
alignment, and multi-layer layouts.

## Explanation Depth

### The first-principles rule

Do not assume the reader knows why a design choice was made. Explain the
reasoning chain:

**Bad:**
> The pipeline splits into a Sender and Drainer for concurrent execution.

**Good:**
> Scanning a file and durably committing its results are both I/O-bound
> operations. If they run sequentially — scan all files, then commit all
> results — the commit stage sits idle during scanning and vice versa.
> Running them concurrently lets the commit stage process completed items
> while scanning continues on the next file.
>
> To enable this, the pipeline splits into two handles: the **Sender**
> (held by the scan thread, submits completed items into a bounded channel)
> and the **Drainer** (held by the commit thread, receives items and feeds
> durable receipts into the checkpoint aggregator). The bounded channel
> provides backpressure: if the commit stage falls behind, the channel fills
> up and the scan thread blocks until space opens.

### Concurrency explanations

Whenever the change involves concurrency (threads, channels, async tasks),
the explanation must cover:

1. **Why concurrent at all?** What would be worse about sequential execution?
2. **What runs in parallel?** Name the specific work that overlaps.
3. **How do they communicate?** Channels, shared state, atomics, etc.
4. **What provides ordering/synchronization?** Bounded channels, join points,
   sequence numbers, etc.
5. **What happens on failure?** Does one side cancel the other? How?

### Structural explanations

When the change introduces new types, traits, or splits existing ones:

1. **What does this type represent?** One sentence, concrete.
2. **Why is it separate from X?** What would go wrong if it were inlined or
   merged?
3. **Who creates it, who consumes it?** Follow the lifecycle.

### Data flow explanations

When data moves between components:

1. **What is the data?** Name the type and what it carries.
2. **Where does it come from?** Who produces it and when.
3. **Where does it go?** Who consumes it and what they do with it.
4. **What transforms happen along the way?** Translation, validation,
   aggregation.

## Anti-Patterns

- Do NOT use Mermaid — output must be readable in a terminal
- Do NOT dump the raw diff — that's what `git diff` is for
- Do NOT list every changed line — focus on what matters architecturally
- Do NOT invent motivation — derive it from the diff, commit messages, and PR description
- Do NOT skip the diagrams — they are the primary value of this skill
- Do NOT create diagrams that show the entire system — zoom in on what changed
- Do NOT put named components in diagrams without explaining them in prose
- Do NOT mention concurrency without explaining why it exists and how it is
  synchronized
- Do NOT say "splits into X and Y" without explaining what X does, what Y
  does, and why they are separate
- Do NOT present a mechanism as a numbered list of steps without first
  explaining *what problem the mechanism solves* and *what the moving pieces
  are*
