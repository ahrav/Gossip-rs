---
name: reduce-complexity
description: >
  Analyze code for complexity hotspots and suggest simplifications. Identifies functions
  exceeding evidence-based LOC and nesting thresholds, classifies complexity as essential
  (domain-inherent, leave alone) or accidental (reducible), and produces actionable
  reduction suggestions with safety annotations. Use PROACTIVELY when: reviewing files
  or modules for maintainability, before refactoring to find highest-ROI targets, triaging
  tech debt, when the user says "simplify", "reduce complexity", "find complex functions",
  "what should I refactor", "maintainability review", "this file is too complex", "hard
  to understand", or asks about code quality or readability of specific files. Also use
  when examining large functions (>100 lines) during code review. Works on any language
  with emphasis on Rust-specific patterns. Does NOT perform automated refactoring -- it
  detects, explains, and suggests.
---

# Code Complexity Reduction

Detect complexity hotspots, classify them as essential or accidental, and suggest
specific reduction techniques with safety annotations. The core value is not metric
computation (Clippy already does that) but explaining WHY code is complex and WHETHER
reduction is safe in context.

## When to use

- Reviewing a file or module for maintainability
- Before refactoring, to identify the highest-ROI targets
- Triaging tech debt across a codebase or directory
- When a function feels hard to understand and you want to know why
- During code review of large or deeply nested functions

## When NOT to use

- For code review (use code-review skills instead)
- For performance optimization (use performance-analyzer)
- For automated refactoring (use refactoring-assistant)
- For style/formatting issues (use cargo fmt / linters)

---

## Input

| Form | Example | Behavior |
|------|---------|----------|
| File path | `/reduce-complexity src/cache.rs` | Analyze all functions in the file |
| Directory | `/reduce-complexity src/` | Scan source files, report top-N hotspots |
| No argument | `/reduce-complexity` | Scan all non-test source files, report top-10 |

Exclude test files (`*_tests.rs`, `tests/`) from default scans unless explicitly passed.
Test code has different complexity norms.

---

## Analysis Pipeline

Execute these four phases in order. Read the target code before starting.

### Phase 1: Detection

Enumerate every function in the target scope. For each, measure:

1. **LOC** -- lines from opening `{` to closing `}`, excluding blanks and comment-only lines
2. **Max nesting depth** -- with the Rust match discount (see below)
3. **Parameter count** -- including `&self`/`&mut self`
4. **Unsafe presence** -- whether the function body contains `unsafe` blocks
5. **Clippy annotations** -- any `#[allow(clippy::...)]` on the function or enclosing impl

Flag a function if ANY independent threshold triggers:

| Metric | Advisory | Moderate | High | Critical |
|--------|----------|----------|------|----------|
| LOC | 51-100 | 101-200 | 201-400 | >400 |
| Nesting | 4 | 5-6 | 7+ | -- |
| Params | 6-7 | 8+ | -- | -- |

Advisory items appear only in the codebase overview unless another metric also triggers.

**Rank** flagged functions by: number of thresholds exceeded (descending), then LOC
(descending). Cap output at 15 functions per file, 25 per directory.

#### Why these metrics, not cyclomatic/cognitive complexity

LOC is the most stable defect predictor across all major studies (Menzies, Hatton,
Lessmann). Cyclomatic complexity correlates with LOC at r > 0.9 -- it catches
nothing LOC misses. Cognitive complexity adds only 5.26% accuracy and the Clippy
team placed their implementation in the `restriction` group as unreliable for Rust.
Independent threshold checks are transparent and evidence-based.

#### Rust match discount

An exhaustive `match` on an enum with <= 6 variants counts as nesting +0 (no increment).
Rust's exhaustive matching is a type-safety mechanism, not decision complexity. A
`match` on `Result<T, E>` or a 4-variant enum is idiomatic.

A `match` on a runtime value (integer, string) or an enum with >6 variants counts
as normal nesting +1.

### Phase 2: Classification

For each flagged function, read it and its surrounding context (enclosing impl,
module doc, called functions). Classify as:

- **ESSENTIAL** -- complexity is inherent to the problem domain; leave alone
- **ACCIDENTAL** -- complexity is reducible; suggestions follow
- **MIXED** -- some essential, some accidental; suggestions target only the accidental part

Use these tests to make the judgment:

1. **Domain necessity**: Would a clean-room reimplementation solving the same problem
   have similar structure? If yes, the complexity is essential.

2. **Error handling**: Does each branch handle a semantically distinct error case with
   distinct recovery (logging, circuit breaker signaling, metrics, cleanup)? If yes,
   the branching is essential -- not reducible by collapsing.

3. **Sequential coupling**: Do steps have data or control dependencies preventing
   reordering? If yes, the sequential length is essential.

4. **Accidental indicators**: Duplicated logic blocks (same pattern 3+ times), deep
   nesting flattenable with early returns, boilerplate extractable to a helper,
   parameters always passed together (struct opportunity), conditions testing
   implementation state rather than domain state.

Include a 1-2 sentence rationale with each classification.

### Phase 3: Suggestions

For ACCIDENTAL and MIXED functions, recommend specific techniques. Read
`references/techniques.md` for the full catalog of 12 techniques with preconditions,
contraindications, and presentation templates.

Techniques are classified by confidence:

| Category | Techniques | Confidence |
|----------|-----------|------------|
| Fully automatable (5) | Guard clauses, redundant else removal, remove unnecessary Result, pass by reference, type aliases | `auto-apply` or `suggest` |
| Judgment-required (4) | Extract function, ? operator, merge match arms, let-else | `suggest` or `flag-for-review` |
| Not automatable (3) | Collapse if-chains, polymorphism, decompose state machine | `flag-for-review` only |

**Never suggest more than 3 techniques per function.** More than 3 signals the
function needs broader redesign, not incremental fixes. Say so explicitly.

### Phase 4: Safety Checks

Apply these checks after generating suggestions. They can override or annotate output.

1. **Unsafe exclusion zone**: If the function contains `unsafe`, or calls a function
   in the same module that contains `unsafe` -- label "MANUAL REVIEW REQUIRED" and
   suppress all suggestions except guard clauses. Unsafe invariants (like `set_len` +
   `truncate`, `#[repr(align)]`, FFI contracts) often span multiple statements and are
   invisible to any analysis.

2. **Clippy annotation respect**: If the function has `#[allow(clippy::...)]`, note
   the developer made a deliberate decision. Do not suppress suggestions but lower
   confidence by one level.

3. **Over-abstraction brake** (for extract-function suggestions):
   - **Shallow module check**: If `param_count + return_type_fields >= body_lines / 3`,
     warn that the extraction interface is nearly as complex as the body.
   - **Single call-site + high coupling**: If the extracted code would be called from
     exactly 1 site AND requires >3 parameters, warn about locality destruction.
   - **Zero intention gap**: If the body is only stdlib/library calls with no domain
     logic, warn that a function name adds no information.

4. **Async boundary warning**: If a suggestion involves extracting code containing
   `.await` points, warn about `Send` bound implications and recommend `cargo check`.

5. **Validation requirement**: Any accepted suggestion must pass `cargo check` +
   `cargo clippy`. Characterization tests alone are insufficient -- they miss
   `Send`/`Sync` violations and lifetime constraint breakages.

---

## Output Format

Structure the report with these four sections:

### Section 1: Hotspot Summary

A ranked table:

```
## Complexity Hotspots

| # | Function | Location | LOC | Nesting | Params | Flags | Class |
|---|----------|----------|-----|---------|--------|-------|-------|
```

Flags use abbreviated severity: `LOC:High`, `Nest:Mod`, `Params:Mod`.
Class is ESSENTIAL, ACCIDENTAL, or MIXED.

### Section 2: Per-Function Analysis

One block per flagged function, in rank order:

```
### #N: `function_name` (file:line) -- CLASSIFICATION

**Metrics:** N LOC | max nesting M | K params
**Flags:** which thresholds triggered

**Why it is complex:** 2-3 sentences explaining the dominant complexity driver.

**Essential vs Accidental:** What is inherent to the domain vs what is structural.

**Suggestions:** (only for ACCIDENTAL/MIXED)
1. TECHNIQUE (confidence): explanation, before/after sketch, impact estimate
   - Over-abstraction check result if applicable
   - Safety warnings if applicable
```

### Section 3: Codebase Health Overview

Aggregate statistics:

```
## Codebase Health

| Metric | Value | Assessment |
|--------|-------|------------|
| Functions exceeding LOC threshold | N / total (%) | vs Pareto norm (10-20%) |
| Functions exceeding nesting threshold | N / total (%) | |
| Essential complexity ratio | N of M flagged (%) | Higher = more domain-inherent |
| Dominant complexity pattern | e.g. "sequential orchestration" | |

**Highest-ROI targets:** Functions with the most accidental complexity and
simplest extraction boundaries.
```

### Section 4: Essential Complexity Warnings

Functions that are complex but should NOT be simplified:

```
## Essential Complexity -- Leave Alone

| Function | Location | Why Essential |
|----------|----------|---------------|
```

Close with: "Complex code takes 124% longer to resolve issues in (CodeScene, 39
codebases). This is a cognitive load effect -- the cost is developer time, not
production failures. Rust's compiler eliminates many defect classes."

---

## Supplementary Signals

When git history is available, use it to adjust ranking priority (not detection):

| Signal | Command | Effect |
|--------|---------|--------|
| Change frequency | `git log --oneline -- <file> \| wc -l` | High-churn functions ranked higher |
| Author count | `git log --format=%aN -- <file> \| sort -u \| wc -l` | Many-author functions ranked higher |
| Recency | `git log --since=90d -- <file>` | Recently changed functions ranked higher |

Process metrics outperform all static code metrics for defect prediction (Moser 2008).
