# PR Explainer Output Template

Use this structure for all PR explanations. Every section is required.
All diagrams must be ASCII box-and-arrow art — no Mermaid.

---

## Why

_1-3 sentences explaining the motivation and problem being solved._
_Derive from: commit messages, PR description, and the nature of the changes._

## Architecture Context

_Where this change fits in the system. Reference specific design docs and
existing diagrams from `docs/` and `diagrams/`._

_Include an ASCII diagram showing the affected boundary/components:_

```
  Boundary N: Name
  ┌───────────────────────────────────────┐
  │                                       │
  │  ┌────────────────┐  ┌────────────┐   │
  │  │ Component A    │  │ Changed [*]│   │
  │  └───────┬────────┘  └─────┬──────┘   │
  │          │                 │           │
  │          └────────┬────────┘           │
  │                   ▼                   │
  │          ┌────────────────┐           │
  │          │ New Thing  [+] │           │
  │          └────────────────┘           │
  └───────────────────────────────────────┘

  [*] = changed   [+] = new
```

_Explain what the diagram shows and how the change relates to the existing
architecture. Mention which design doc(s) govern this area._

## What Changed

_High-level summary of the approach — what was added, modified, or removed
and why that approach was chosen._

_Include an ASCII diagram showing the change itself (data flow, state
transitions, or structural relationships):_

```
  Before:                       After:
  ┌──────────┐                  ┌──────────────┐
  │ old flow │ ──────────────▶  │ new flow     │
  └──────────┘                  └──────────────┘
```

## Key Decisions

_Non-obvious design choices and trade-offs. Why was this approach chosen
over alternatives? What constraints shaped the design?_

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
