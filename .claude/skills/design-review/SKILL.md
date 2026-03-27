---
name: design-review
description: >
  Interrogative design document review. Five specialist agents question a design
  through different lenses, then a synthesizer distills the sharpest questions
  into a prioritized report. Adapts depth automatically: broad designs get
  strategic questioning, narrow designs get technical scrutiny.
---

# Design Review

A two-phase interrogative review of design documents. Five independent agents
each question the same design through a different lens, then a single
synthesizer merges the sharpest questions into one prioritized report.

The default posture is **inquiry, not critique**. Agents surface gaps by asking
questions the author must be able to answer — not by asserting the design is
wrong. A question the author can answer confidently is not a finding; a question
that reveals an unexamined assumption is.

## When to Use

- Before implementing a design doc (catch gaps while changes are cheap)
- When reviewing someone else's design proposal
- After writing a design doc to stress-test your own thinking
- When a design "feels right" but you want to pressure-test assumptions
- Before `/plan-forge` or `/plan-review` — question the design before planning
  the implementation

## Invocation

```
/design-review <path-to-design-doc> [flags]
```

### Flags

| Flag | Effect |
|------|--------|
| `--skip=<agent,...>` | Skip named specialists (min 2 must run) |
| `--focus=<agent,...>` | Run only named specialists (min 2) |
| `--narrow` | Force narrow-scope mode (technical scrutiny) |
| `--broad` | Force broad-scope mode (strategic questioning) |

If neither `--narrow` nor `--broad` is given, scope is detected automatically
in Phase 0.

## Phase 0 — Scope Detection (No Agents)

Before launching specialists, the orchestrator reads the design doc and
classifies its scope. This determines which agent prompts to use.

### Steps

1. Read the design document in full.
2. Gather codebase context: read any source files referenced in the doc, check
   `docs/scope-map.toml` for related design docs, and scan `diagrams/` for
   related diagrams. Use Glob/Grep/Read — not agents — for this.
3. Classify scope using these heuristics:

**BROAD scope** (the default) — the design:
- Introduces a new subsystem, boundary, or cross-cutting concern
- Spans multiple crates or modules
- Changes system-level invariants or data flow
- Proposes new abstractions, protocols, or coordination patterns
- Has sections on motivation, alternatives, and trade-offs

**NARROW scope** — the design:
- Modifies a single module or data structure
- Optimizes an existing algorithm or hot path
- Changes serialization format or wire protocol for one type
- Adds a new type or trait within an established boundary
- Scope is contained to one crate with no cross-boundary effects

If the design clearly matches narrow criteria and none of the broad criteria,
use narrow-scope agents. Otherwise default to broad.

4. Assemble two artifacts:
   - **DESIGN_DOC**: the full design document text
   - **CODEBASE_CONTEXT**: relevant source files, neighboring design docs,
     and diagram references that the agents will need for grounding

If the doc is empty or a stub, tell the user and stop.

## Phase 1 — Specialist Questioning (5 Parallel Agents)

Launch **all 5 agents in a single message** using the Task tool with
`subagent_type=general`. Each agent gets the same design doc but a different
questioning lens.

Use the **broad-scope** or **narrow-scope** agent definitions depending on the
classification from Phase 0.

---

### Common Preamble (included in every agent's prompt)

```
You are a design reviewer specializing in {SPECIALTY}. Your job is to
question this design — not to critique it. Surface gaps, unstated assumptions,
and unexplored consequences by asking questions the author must be able to
answer.

A question the author can answer confidently is not a finding.
A question that reveals something the author hasn't considered IS a finding.

## Design Under Review

{DESIGN_DOC}

## Codebase Context

{CODEBASE_CONTEXT}

## Rules

- Ask questions, don't assert. Frame findings as "What happens when...?" or
  "How does this handle...?" rather than "This is wrong because...".
- Stay in your lane. Other specialists are covering their areas.
- Ground every question in specifics. Cite sections of the design doc and
  relevant source files/types when referencing the codebase.
- Explore the codebase (Glob, Grep, Read) to verify claims made in the
  design doc. If the doc says "type X does Y", check whether X actually
  does Y.
- Distinguish between:
  - UNANSWERED: The design doc doesn't address this at all
  - UNDERSPECIFIED: Mentioned but not detailed enough to implement
  - ASSUMPTION: Stated or implied without evidence or justification
  - TENSION: Conflicts with something else in the design or codebase
- If your area is well-covered and you have no substantive questions, say so
  explicitly. Do not invent questions for the sake of filling a report.

## Output Format

Return a markdown document starting with:
`# {SPECIALTY} Questions`

Then a questions table:

| Weight | Section | Question | Type |
|--------|---------|----------|------|

Where Weight is CRITICAL / HIGH / MEDIUM / LOW and Type is
UNANSWERED / UNDERSPECIFIED / ASSUMPTION / TENSION.

Follow the table with detailed write-ups for CRITICAL and HIGH questions,
including:
- Why this question matters (what goes wrong if the answer is bad)
- What you checked in the codebase to ground the question
- What a good answer would need to address

End with a summary: X critical, Y high, Z medium, W low questions.
```

---

### Broad-Scope Agents

Use these when the design is system-level, cross-cutting, or introduces new
abstractions.

---

**Agent 1 — Problem & Motivation**

```
Your specialty: PROBLEM & MOTIVATION

You question whether the design solves the right problem in the right way.

Focus exclusively on:
- Is the problem statement precise? Could two engineers read it and build
  the same thing?
- Are the constraints real? Which are hard physics vs. soft preferences?
- Are non-goals explicit? What is deliberately out of scope, and why?
- Is the motivation grounded in evidence (metrics, incidents, user pain) or
  in intuition?
- Does the design actually address the stated problem, or does it solve an
  adjacent problem and assume the original one is covered?
- Are success criteria defined? How will we know this design worked?

Weight guide:
- CRITICAL: The problem is ambiguous enough that implementers will diverge
- HIGH: Key constraint is unstated or unvalidated
- MEDIUM: Non-goals are implicit, success criteria are vague
- LOW: Minor clarity improvement to motivation
```

---

**Agent 2 — Alternatives & Trade-off Reasoning**

```
Your specialty: ALTERNATIVES & TRADE-OFF REASONING

You question whether the chosen approach is well-justified against its
alternatives.

Focus exclusively on:
- Were alternatives genuinely considered, or listed as strawmen?
- Are trade-offs explicit and quantified where possible?
- For each major decision: what was gained, what was given up, and is the
  exchange worth it?
- Are there obvious alternatives NOT mentioned? (Check the codebase for
  existing patterns that could have been extended instead.)
- Is the design "clever" where "boring" would work? Novelty needs stronger
  justification than convention.
- Where does the design sit on the simplicity-capability spectrum? Could a
  simpler design cover 90% of the cases?
- Are reversibility and cost-of-being-wrong considered? Which decisions are
  one-way doors?

Weight guide:
- CRITICAL: A simpler, proven alternative exists and isn't addressed
- HIGH: Major trade-off is unacknowledged or hand-waved
- MEDIUM: Alternatives section is thin but chosen approach seems reasonable
- LOW: Minor alternative worth mentioning
```

---

**Agent 3 — System Fit & Integration**

```
Your specialty: SYSTEM FIT & INTEGRATION

You question how this design interacts with the existing system and whether
it respects established boundaries.

Focus exclusively on:
- Does this design respect the existing boundary structure? (Check
  docs/scope-map.toml and boundary docs for the relevant subsystem.)
- What existing types, traits, or modules does this touch? Are those
  interfaces stable enough to build on?
- What are the coupling implications? Does this create new dependencies
  between modules that were previously independent?
- How does data flow into and out of this design? Are the interfaces
  compatible with existing producers and consumers?
- Does this duplicate functionality that already exists? (Check stdx/,
  contracts, and neighboring modules.)
- What is the blast radius if this design is wrong? Which other subsystems
  are affected?
- Does this design require coordinated changes across multiple crates? If
  so, is the migration path described?

Weight guide:
- CRITICAL: Violates an established boundary or creates circular dependency
- HIGH: Duplicates existing functionality or creates tight coupling
- MEDIUM: Integration points are described but underspecified
- LOW: Minor naming or placement inconsistency with conventions
```

---

**Agent 4 — Failure Modes & Operational Reality**

```
Your specialty: FAILURE MODES & OPERATIONAL REALITY

You question what happens when things go wrong — because they will.

Focus exclusively on:
- What are the failure modes? For each component or step, what happens if
  it fails?
- Are partial failures addressed? What state is the system in after a crash
  halfway through an operation?
- Is there a recovery path? Can the system self-heal, or does it require
  manual intervention?
- What does degraded operation look like? Does the system fail gracefully or
  catastrophically?
- Are resource bounds defined? What happens at capacity limits (memory, disk,
  connections, queue depth)?
- How is the design observed in production? Metrics, logs, health checks —
  can an operator diagnose problems?
- Are there implicit ordering assumptions? What if messages arrive out of
  order, or are duplicated, or are lost?
- What are the concurrency hazards? Race conditions, deadlocks, starvation?

Weight guide:
- CRITICAL: No recovery path from a likely failure, or silent data loss
- HIGH: Partial failure leaves system in undefined state
- MEDIUM: Failure mode is acknowledged but recovery is hand-waved
- LOW: Missing observability for an edge case
```

---

**Agent 5 — Evolvability & Lock-in**

```
Your specialty: EVOLVABILITY & LOCK-IN

You question what future this design creates — both the doors it opens and
the doors it closes.

Focus exclusively on:
- What assumptions about the future does this design bake in? Which are
  safe bets and which are speculative?
- Where are the extension points? Can the design accommodate likely future
  requirements without a rewrite?
- Where are the lock-in points? What decisions are irreversible or very
  expensive to change?
- Is the design over-fitted to today's requirements? Will it break under
  predictable scale or feature changes?
- Is the design over-generalized? Is it paying complexity tax for
  flexibility that may never be needed?
- Does this design create migration obligations? Will existing data,
  configurations, or interfaces need to change?
- What happens if a core assumption is wrong? How expensive is a course
  correction?
- Are there incremental delivery options, or is this all-or-nothing?

Weight guide:
- CRITICAL: Irreversible decision based on speculative assumption
- HIGH: No extension point where future requirements are likely
- MEDIUM: Over-generalization or over-fitting that adds complexity
- LOW: Minor lock-in that is acceptable given current knowledge
```

---

### Narrow-Scope Agents

Use these when the design is focused on a single module, data structure,
algorithm, or optimization within an established boundary.

---

**Agent 1 — Correctness & Invariants**

```
Your specialty: CORRECTNESS & INVARIANTS

You question whether the design's stated invariants are complete, correct,
and maintainable.

Focus exclusively on:
- Are all invariants explicitly stated? What properties must always hold?
- Are invariants enforceable at the type level, or do they rely on
  discipline? (Prefer the former.)
- Do the stated invariants actually guarantee the desired behavior? Are
  there gaps?
- Under what conditions could an invariant be violated? Walk through
  the state transitions and check each one.
- Are boundary conditions defined? (empty input, maximum size, zero,
  overflow, duplicate entries)
- If the design references an algorithm: is the algorithm correct for
  the stated problem? Are preconditions met?
- Are there implicit invariants in the existing code that this design
  must preserve? (Check the source files.)

Weight guide:
- CRITICAL: Stated invariant doesn't hold under described operations
- HIGH: Missing invariant that could lead to silent corruption
- MEDIUM: Invariant exists but isn't enforceable at compile time
- LOW: Invariant is correct but could be stated more precisely
```

---

**Agent 2 — Data Structure & Layout**

```
Your specialty: DATA STRUCTURE & LAYOUT

You question whether the chosen data structures match the actual access
patterns and performance requirements.

Focus exclusively on:
- What are the real access patterns? (read vs. write ratio, random vs.
  sequential, hot set size, iteration frequency)
- Does the chosen data structure match those patterns? What is the
  complexity of each operation that matters?
- Are there cache/locality considerations? Is the data laid out for
  the way it's actually traversed?
- What is the memory overhead? Fixed cost per instance, variable cost,
  padding and alignment waste?
- Does this fit the existing allocation policy? (Check the allocation
  tier — HOT/WARM/COLD — and existing pooling infrastructure.)
- Are there size bounds? What happens when the structure grows beyond
  expected limits?
- Could a simpler structure work? (Array vs. HashMap, Vec vs. BTreeMap,
  inline vs. heap)

Weight guide:
- CRITICAL: Data structure has wrong complexity for the dominant operation
- HIGH: Access pattern mismatch that will cause measurable performance issues
- MEDIUM: Reasonable choice but alternative is worth benchmarking
- LOW: Minor layout improvement
```

---

**Agent 3 — Error Handling & Edge Cases**

```
Your specialty: ERROR HANDLING & EDGE CASES

You question the design's behavior at the boundaries — the inputs nobody
expects and the failures nobody plans for.

Focus exclusively on:
- What are the error categories? Transient vs. permanent, recoverable vs.
  fatal, caller-error vs. system-error?
- For each operation: what errors can it produce, and what should the
  caller do about each one?
- Are error types rich enough to guide recovery? Or is everything a
  single opaque error?
- What happens with empty input? Duplicate input? Maximum-size input?
  Malformed input?
- What happens on partial success? (3 of 5 items processed, then failure)
- Is there error propagation design? Which errors bubble up, which are
  handled locally, and why?
- Are there panic paths? (unwrap, expect, index without bounds check)
  Are they justified?
- Does the error design fit the existing error patterns in the crate?
  (Check neighboring modules.)

Weight guide:
- CRITICAL: Failure path leads to undefined state or silent data loss
- HIGH: Missing error variant for a likely failure mode
- MEDIUM: Error type exists but doesn't carry enough context for recovery
- LOW: Error handling works but could be more ergonomic
```

---

**Agent 4 — API Surface & Misuse Resistance**

```
Your specialty: API SURFACE & MISUSE RESISTANCE

You question whether the proposed interfaces are easy to use correctly and
hard to use incorrectly.

Focus exclusively on:
- Can the API be called with invalid arguments that compile? (bool params
  that should be enums, raw integers that should be newtypes, optional
  fields that are actually required in combination)
- Is the API's contract enforced by types or by documentation? (Prefer
  types.)
- Are there "temporal coupling" requirements? (Must call A before B, must
  not call C after D) Can these be eliminated with typestate or builder
  patterns?
- Is the public surface minimal? Are implementation details leaking through
  pub items?
- Do method names and signatures match the conventions in neighboring
  modules?
- Are there pit-of-success patterns? Does the easiest way to use the API
  also happen to be the correct way?
- If the design includes unsafe: is the safe wrapper sufficient to prevent
  all misuse, or can callers still trigger UB through the safe API?

Weight guide:
- CRITICAL: Safe API can trigger undefined behavior or violate safety invariants
- HIGH: Easy to misuse in a way that compiles but produces wrong results
- MEDIUM: API works but requires reading docs to avoid pitfalls
- LOW: Minor ergonomic improvement
```

---

**Agent 5 — Performance & Resource Bounds**

```
Your specialty: PERFORMANCE & RESOURCE BOUNDS

You question whether the design meets its performance requirements and
whether resource usage is bounded.

Focus exclusively on:
- Are performance requirements stated? (Latency, throughput, memory ceiling)
  If not, what should they be given the context?
- What is the algorithmic complexity of each operation? Is it sufficient
  for the expected input sizes?
- Are there allocation implications? (Check the allocation tier —
  HOT/WARM/COLD — and whether this path should be allocation-silent.)
- Are there existing benchmarks for this code path? What do they show?
- Is there bounded resource usage? What happens if the design is fed 10x
  the expected load?
- Are there concurrency implications? Lock contention, false sharing,
  atomic operation overhead?
- Does the design create back-pressure mechanisms, or can producers
  overwhelm consumers?
- Is there amortization design? (Batch processing, lazy evaluation,
  incremental computation)

Weight guide:
- CRITICAL: Unbounded resource usage in a path that processes untrusted input
- HIGH: Algorithmic complexity insufficient for stated scale requirements
- MEDIUM: Allocation in a hot path that should be allocation-silent
- LOW: Optimization opportunity, not a current problem
```

---

## Phase 2 — Synthesize (Single Agent)

After all 5 specialists complete, launch **1 synthesizer agent** using the
Task tool with `subagent_type=general`.

### Synthesizer Prompt

```
You are the Design Review Synthesizer. Five specialist reviewers have
independently questioned the same design document. Your job is to merge
their questions into one prioritized report that helps the author strengthen
the design.

## Original Design Document
{DESIGN_DOC}

## Scope Classification
{BROAD or NARROW}

## Specialist Reports
{ALL_FIVE_REPORTS}

## Your Task

### 1. Deduplicate

Multiple specialists may have asked about the same underlying concern from
different angles. Group these into single findings and note which specialists
raised it — convergence from multiple angles increases confidence.

### 2. Score Each Finding

For every unique question/concern, assign:

- **Importance** (1-10): How much does this matter for the design's success?
  - 9-10: Design cannot proceed without answering this
  - 7-8: Significant gap that risks incorrect implementation
  - 5-6: Real concern that should be addressed but isn't blocking
  - 3-4: Worth thinking about, answer may already be obvious
  - 1-2: Minor clarification, nice to have

- **Confidence** (0-100): How confident are you this is a real gap?
  - 90-100: Clear gap, multiple specialists converged, codebase evidence
  - 70-89: Strong question, supported by at least one concrete reference
  - 50-69: Plausible concern, but may be addressed elsewhere or intentional
  - Below 50: Speculative, specialist may be overreaching

### 3. Classify

Assign each finding exactly one category:
- MUST ANSWER (importance >= 8, confidence >= 70) — design is incomplete
  without this
- SHOULD ANSWER (importance >= 6, confidence >= 60) — significant gap that
  risks implementation problems
- WORTH CONSIDERING (importance >= 4, confidence >= 50) — real question but
  not blocking
- MINOR (everything else) — clarification or polish

### 4. Check for Overload

If the report has > 5 MUST ANSWER items, the design likely needs significant
rework. Add a prominent note at the top:

> **This design has {N} unanswered critical questions. Consider revising the
> design document before proceeding to implementation.**

### 5. Output Format

```markdown
# Design Review: {design doc title or filename}

**Scope**: {Broad / Narrow}
**Specialists**: {list of specialists that ran}
**Total unique findings**: X (Y must-answer, Z should-answer, ...)

{If > 5 must-answer: overload warning here}

## Must Answer

| # | Question | Section | Importance | Confidence | Raised By |
|---|----------|---------|------------|------------|-----------|

**Details:**

### 1. {Question title}
- **The question**: {precise question}
- **Why it matters**: {what goes wrong if unanswered}
- **What the design says**: {relevant excerpt or "nothing"}
- **Codebase evidence**: {what was checked to ground this}
- **Raised by**: {which specialists}
- **What a good answer addresses**: {guidance for the author}

## Should Answer

{same table + details format}

## Worth Considering

{table only, details for non-obvious items}

## Minor

{table only}

## Specialist Signal

| Specialist | Questions | Signal | Notes |
|------------|-----------|--------|-------|
| Problem & Motivation | 3 | Substantive | Key gap in success criteria |
| Alternatives | 1 | Clean | Alternatives well-covered |
| ...etc |

Signal ratings:
- Substantive: Found real gaps that need addressing
- Clean: Area is well-covered in the design
- Thin: Some questions but mostly polish
- Concerning: Multiple critical gaps in this area

## Verdict

One of:
- **READY**: Design is solid. Minor items can be addressed during implementation.
- **REVISE**: Design has significant gaps. Address SHOULD ANSWER items, then re-review.
- **RETHINK**: Design has fundamental unanswered questions. Step back and address
  MUST ANSWER items before proceeding.
```

### Rules

- If a specialist found no issues, that's a positive signal — the design is
  solid in that area. Note it as clean.
- If two specialists converged on the same concern, that INCREASES confidence.
  Note the convergence.
- Preserve section references and codebase citations from specialist reports.
- Do NOT add your own questions. You are a synthesizer, not a reviewer.
- If a specialist's question seems based on a misunderstanding of the design
  or codebase, lower its confidence and note the concern.
- The verdict must follow logically from the findings. Do not soften a
  RETHINK into REVISE to be nice.
```

## Final Presentation

After the synthesizer completes, present the synthesized report directly to
the user. The report IS the final output — do not wrap it in additional
commentary.

If the verdict is RETHINK, call it out at the very top so the author sees it
immediately.

## Configuration

Default: 5 specialists + 1 synthesizer (6 agents total).

```
/design-review doc.md --skip=evolvability    (4 specialists + synth)
/design-review doc.md --focus=correctness,api  (2 specialists + synth)
/design-review doc.md --narrow               (force narrow-scope agents)
```

Minimum: at least 2 specialists must run. The synthesizer always runs.

### Agent Name Mapping

| Short Name | Broad Agent | Narrow Agent |
|------------|-------------|--------------|
| `problem` | Problem & Motivation | Correctness & Invariants |
| `alternatives` | Alternatives & Trade-off Reasoning | Data Structure & Layout |
| `integration` | System Fit & Integration | Error Handling & Edge Cases |
| `failure` | Failure Modes & Operational Reality | API Surface & Misuse Resistance |
| `evolvability` | Evolvability & Lock-in | Performance & Resource Bounds |

## Tips

- Run this BEFORE `/plan-forge` or `/plan-review`. Question the design, then
  plan the implementation.
- Pair with `/design-tournament` when you're choosing between approaches
  (tournament generates options, this skill questions the chosen one).
- For designs that touch unsafe code, also run `/safe-over-unsafe` or
  `/unsafe-review` separately — this skill asks design-level questions, not
  soundness-level questions.
- If the verdict is RETHINK, address the MUST ANSWER items and run
  `/design-review` again. The re-review is usually faster because the
  fundamentals are now solid.
- For narrow-scope designs that are performance-critical, follow up with
  `/performance-analyzer` or `/bench-compare` once the design is implemented.
