# PR Explainer Output Template

Use this structure for all PR explanations. Every section is required.
All diagrams must be ASCII box-and-arrow art — no Mermaid.

The guiding principle is **incremental understanding**: introduce a concept
before using it, explain a component before putting it in a diagram, and
motivate a design choice before presenting the design.

---

## The Problem

_What is broken, missing, or inadequate — stated concretely. Not "adds X" but
"without X, the system cannot do Y because Z." The reader should understand
why this work matters before seeing any code._

_If the change is a refactor, explain what was wrong with the previous
structure (fragility, missing extension point, violated invariant, etc.)._

## The Approach

_One paragraph summarizing the solution shape at the highest level. This is
the "elevator pitch" — if the reader stops here, they should have a correct
mental model of what the PR does, even if they don't know the details._

## Architecture Context

_Where this change fits in the existing system. Reference specific design
docs and existing diagrams from `docs/` and `diagrams/`._

_Include an ASCII diagram showing the affected boundary and components.
Every component shown must be explained in the surrounding text:_

```
  Boundary N: Name
  ┌───────────────────────────────────────┐
  │                                       │
  │  ┌────────────────┐  ┌────────────┐   │
  │  │ Component A    │  │ Changed [*]│   │
  │  └───────┬────────┘  └─────┬──────┘   │
  │          │                 │           │
  │          └────────┬────────┘           │
  │                   ▼                    │
  │          ┌────────────────┐            │
  │          │ New Thing  [+] │            │
  │          └────────────────┘            │
  └───────────────────────────────────────┘

  [*] = changed   [+] = new
```

_After the diagram, explain: "Component A does X. Changed [*] previously
did Y but now does Z. New Thing [+] was added because..."_

## How It Works

_This is the core section. Walk through the mechanism step by step, building
understanding incrementally. Follow this pattern:_

### 1. Introduce the moving pieces

_Before showing any diagram or sequence, define each component that
participates. For each one:_
- _What is it? (one sentence)_
- _Why does it exist as a separate thing? (what would break if it didn't?)_

_Example:_
> **ResultCommitter** — takes translated persistence rows and writes them
> durably to the findings sink and done-ledger, in that order. It exists as
> a separate stage (rather than inline code) because the write ordering
> invariant (findings before done-ledger) must be enforced in exactly one
> place.

### 2. Explain the data flow

_What data moves between the components, in what order, and through what
mechanisms (function calls, channels, shared state). If there is
concurrency, explain it here:_

- _Why concurrent? What would be slower or broken if it ran sequentially?_
- _What runs in parallel? Name the specific overlapping work._
- _How do the parallel paths communicate? (channels, atomics, join points)_
- _What provides backpressure or ordering? (bounded channels, sequence numbers)_
- _What happens on failure? (cancellation, rollback, retry)_

### 3. Show the mechanism diagram

_Now that every component has been introduced and the data flow explained,
show a diagram that makes the structure visible. The reader should be able
to match every box and arrow back to the prose above._

```text
  Thread 1 (scan)              Thread 2 (commit)
  ┌──────────────────┐         ┌───────────────────┐
  │ scan files       │         │ commit results    │
  │ ──▶ translate    │         │ ──▶ record receipt│
  │ ──▶ submit       │─items──▶│ ──▶ aggregate     │
  │     (blocks if   │ bounded │     checkpoint    │
  │      queue full) │ channel │                   │
  └──────────────────┘         └───────────────────┘
           │                            │
           └──── join point ────────────┘
                     │
                     ▼
           ┌──────────────────┐
           │ cross-check      │
           │ submitted ==     │
           │ committed counts │
           └──────────────────┘
```

_After the diagram, annotate anything that isn't obvious: "The bounded
channel between Thread 1 and Thread 2 serves as backpressure — when the
commit stage falls behind, the channel fills and scanning pauses."_

### 4. Before/after comparison (when modifying existing behavior)

_If the change modifies existing behavior, show what changed structurally:_

```
  Before:                       After:
  ┌──────────┐                  ┌──────────────┐
  │ old flow │ ──────────────▶  │ new flow     │
  └──────────┘                  └──────────────┘
```

_Label the key structural difference._

## Key Decisions

_Non-obvious design choices and trade-offs. For each decision:_

1. _What was the choice?_
2. _What constraint or goal drove it?_
3. _What alternative was rejected (if any) and why?_

_Example:_
> **Single-worker enforcement.** The receipt sink assigns sequence numbers
> using `AtomicU64::fetch_add(Relaxed)`. Atomic RMW guarantees unique IDs
> regardless of ordering; however, `Relaxed` provides no synchronization
> with surrounding state (the in-flight map, findings buffer, and sequence
> ordering all rely on single-threaded access). Rather than upgrading to
> `SeqCst` (which adds fence overhead on every item), the runtime forces
> `workers=1` for distributed scans. This is acceptable because distributed
> shards are already parallelized at the shard level, not the intra-shard
> level.

_If there are no notable decisions, write "Straightforward implementation —
no non-obvious trade-offs."_

## Detailed Changes

_File-by-file breakdown for those who want it. Group by module/boundary,
not alphabetically. For each group:_

| File | Change |
|------|--------|
| `path/to/file.rs` | Brief description of what changed and why |

_Keep descriptions to one line each. This section is a reference index,
not a narrative._
