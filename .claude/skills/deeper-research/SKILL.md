---
name: deeper-research
description: Use when /deep-research isn't thorough enough, when a topic needs adversarial challenge and deep-dive elaboration, or when producing a polished research report for a complex design decision. 6-phase funnel with 8-10 parallel survey agents plus adversarial review.
---

# Deeper Research

A six-phase evidence-gathering funnel for problems where the cost of a wrong
design exceeds the cost of thorough research. Doubles the agent count of
`/deep-research` (21-23 agents vs 7), approaches the problem from 8-10
independent lenses, and adds adversarial review to challenge conclusions before
they reach the implementation plan.

The funnel narrows progressively: a wide initial survey generates raw findings,
synthesis distills them, parallel deep-dives and adversarial challenges stress-
test the synthesis from both directions, a final synthesis reconciles all
streams, and an integrator grounds everything in the codebase with full
traceability from finding IDs to implementation steps.

## When to Use

- **Highest-stakes design decisions**: foundational architecture, core data
  structures, protocols that are impossible to change later
- **Novel or unfamiliar territory at scale**: combining multiple research
  domains where cross-pollination matters
- **When `/deep-research` isn't enough**: you need adversarial challenge of
  findings, deeper dives into gaps, and full traceability
- **Safety-critical + performance-critical intersection**: where you need both
  theoretical correctness AND production evidence
- **When the problem is worth 21+ agent invocations**: this is expensive by
  design

## When NOT to Use

- Use `/deep-research` for standard research tasks (7 agents, 3 phases)
- Use `/design-tournament` when the problem is understood and you need to
  explore implementation approaches
- Straightforward features or well-understood domains
- Problems with clear single solutions

## Invocation

```
/deeper-research <problem statement>
/deeper-research --lenses=10 <problem>        # Full 10 lenses (default: 8)
/deeper-research --lenses=5 <problem>         # Minimal (5 core lenses)
/deeper-research --no-adversarial <problem>   # Skip Phase 4
/deeper-research --skip-deep-dive <problem>   # Skip Phase 3
```

If no argument is given, ask the user for the problem statement before
proceeding.

## Architecture

```
Orchestrator: Problem Decomposition (inline, produces Research Brief)
      |
Phase 1: Wide Survey (8-10 parallel agents)
      |
Phase 2: First Synthesis (1 agent)
      |
      +--- Phase 3: Deep-Dives (3-5 parallel) ---+
      |                                            |  <- run in parallel
      +--- Phase 4: Adversarial (4 parallel)  ----+
      |                                            |
      +--------------------------------------------+
      |
Phase 5: Final Synthesis (1 agent)
      |
Phase 6: Integration (1 agent)
```

**Key structural decision**: Phase 3 and Phase 4 run in parallel in a single
message. This saves a serial step and creates an information firewall —
adversarial agents challenge Phase 2's conclusions independently of Phase 3's
elaborations, preventing anchoring bias.

### Finding ID Scheme (Traceability)

Every finding gets a traceable ID used through all subsequent phases:

```
P1.{agent#}.F{n}  — Phase 1, Agent 4, Finding 3 -> P1.4.F3
S1.F{n}           — First Synthesis findings
P3.{agent#}.F{n}  — Deep-dive findings
P4.{agent#}.F{n}  — Adversarial findings
S2.F{n}           — Final Synthesis findings
```

Every step in Phase 6's implementation plan cites these IDs.

### Output Budgets Per Phase

| Phase | Agents | Max Per Agent | Total to Next Phase |
|-------|--------|---------------|---------------------|
| 1     | 8-10   | ~3000 tokens  | ~24-30k -> Phase 2  |
| 2     | 1      | ~6000 tokens  | 6k -> Phases 3, 4, 5 |
| 3     | 3-5    | ~4000 tokens  | ~12-20k -> Phase 5  |
| 4     | 4      | ~2500 tokens  | ~10k -> Phase 5     |
| 5     | 1      | ~8000 tokens  | 8k -> Phase 6       |
| 6     | 1      | unconstrained | final output        |

### Evidence Strength Scale

Used by ALL agents across all phases.

| Level | Label | Description | Example |
|-------|-------|-------------|---------|
| 5 | **Proven at scale** | Battle-tested in production systems handling similar workloads | FoundationDB's simulation testing, TigerBeetle's storage engine |
| 4 | **Peer-reviewed** | Published in reputable venue with formal analysis | OSDI/SOSP paper with proofs |
| 3 | **Implemented & tested** | Open-source implementation with benchmarks/tests | Well-maintained crate with >1k stars, comprehensive test suite |
| 2 | **Documented practice** | Technical blog from credible engineering org | Blog post from Cloudflare, Datadog, AWS engineering |
| 1 | **Anecdotal** | Forum discussion, personal blog, Stack Overflow answer | Useful for leads but needs corroboration |

---

## Orchestrator: Problem Decomposition (Inline)

Before launching Phase 1, the orchestrator (you) produces a **Structured
Research Brief**. This is NOT a separate agent — do this inline.

### Steps

1. **Parse the problem statement** and identify:
   - Core sub-problems (2-5 distinct questions to answer)
   - Key search terms and domain-specific vocabulary
   - Constraints from the problem statement

2. **Quick codebase scan**: Use Glob, Grep, and Read to gather:
   - Relevant file paths and module structure
   - Existing patterns and conventions
   - Current approach (if any) to the problem
   - Dependencies and their versions

3. **Select lenses**: Based on the problem, select which of the 10 research
   lenses are active (default: 8 core lenses; with `--lenses=10` add the two
   optional lenses; with `--lenses=5` use lenses 1-5 only).

4. **Produce the Research Brief** in this format:

```markdown
## Research Brief

### Problem Statement
{user's problem, restated for clarity}

### Sub-Problems
1. {sub-problem 1}
2. {sub-problem 2}
...

### Key Search Terms
- {term 1}: {why it matters}
- {term 2}: {why it matters}
...

### Codebase Context
- {file path}: {what it contains and why it's relevant}
...

### Active Lenses
{numbered list of selected lenses with brief rationale for optional ones}

### Constraints
- {constraint from problem or codebase}
...
```

Include this Research Brief in every Phase 1 agent's prompt.

---

## Phase Prompts

All phase agent prompts (Phases 1-6, output format, and collecting instructions)
are in [references/phase-prompts.md](references/phase-prompts.md).

The prompts follow this progression:

| Phase | Agents | Role | Input |
|-------|--------|------|-------|
| 1 | 8-10 parallel | Wide survey from independent lenses | Research Brief |
| 2 | 1 | Cross-reference + gap identification | All Phase 1 reports |
| 3 | 3-5 parallel | Deep-dive into Phase 2 gaps | Phase 2 targets |
| 4 | 4 parallel | Adversarial challenge of Phase 2 | Phase 2 synthesis |
| 5 | 1 | Reconcile all streams | Phases 2+3+4 |
| 6 | 1 | Map to implementation plan | Phase 5 synthesis |

---

## Configuration

```
/deeper-research <problem>                    # Default: 8 lenses
/deeper-research --lenses=10 <problem>        # Full 10 lenses
/deeper-research --lenses=5 <problem>         # Minimal (5 core lenses)
/deeper-research --no-adversarial <problem>   # Skip Phase 4
/deeper-research --skip-deep-dive <problem>   # Skip Phase 3
```

### Agent Counts by Configuration

| Config | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 | Phase 6 | Total |
|--------|---------|---------|---------|---------|---------|---------|-------|
| Default (8 lenses) | 8 | 1 | 3-5 | 4 | 1 | 1 | 18-20 |
| Full (10 lenses) | 10 | 1 | 3-5 | 4 | 1 | 1 | 20-22 |
| Minimal (5 lenses) | 5 | 1 | 3-5 | 4 | 1 | 1 | 15-17 |
| No adversarial | 8 | 1 | 3-5 | 0 | 1 | 1 | 14-16 |
| Skip deep-dive | 8 | 1 | 0 | 4 | 1 | 1 | 15 |
| Both skipped | 8 | 1 | 0 | 0 | 1 | 1 | 11 |

### Phase Skip Behavior

- **`--no-adversarial`**: Phase 4 is skipped entirely. Phase 5 synthesizes
  Phase 2 + Phase 3 only (no adversarial reconciliation). Phase 6 has no
  adversarial concerns to address.
- **`--skip-deep-dive`**: Phase 3 is skipped entirely. Phase 4 still runs
  (challenging Phase 2). Phase 5 synthesizes Phase 2 + Phase 4 only.
- **Both flags**: Phases 3 and 4 both skipped. Phase 5 receives only Phase 2's
  synthesis (effectively a pass-through with updated formatting). Consider
  using `/deep-research` instead.

### Minimum Agent Requirements

- Phase 1: minimum 5 agents must succeed (of 8-10 launched)
- Phase 2: exactly 1 (required)
- Phase 3: minimum 2 agents must succeed (of 3-5 launched)
- Phase 4: minimum 3 agents must succeed (of 4 launched)
- Phase 5: exactly 1 (required)
- Phase 6: exactly 1 (required)

## Tips

- **Problem statement quality matters**: Include domain-specific terminology,
  relevant file paths, and specific constraints. The Research Brief amplifies
  this, but garbage in = garbage out.
- **Use `--lenses=10` for cross-cutting concerns**: When the problem spans
  multiple domains (e.g., a data structure that needs both formal correctness
  AND API ergonomics), the optional lenses provide crucial coverage.
- **Use `--lenses=5` when you need more depth, not breadth**: If the problem
  is narrow but deep, 5 lenses with deep-dives gives better results than 10
  surface-level surveys.
- **The adversarial phase is the key differentiator**: It catches overconfidence,
  citation errors, and hidden assumptions. Only skip it (`--no-adversarial`) for
  exploratory research where you don't need verified conclusions.
- **Deep-dives are targeted, not redundant**: They investigate specific gaps
  from Phase 2, not the same questions as Phase 1. Phase 2's Deep-Dive Targets
  section is critical for this.
- **Traceability is the contract**: Every implementation step in Phase 6 must
  cite finding IDs. If a step has no citations, it's unjustified.
- **This skill feeds into `/design-tournament`**: Use deeper-research to
  establish the evidence base, then design-tournament to explore implementation
  approaches grounded in that evidence.
- **For the most critical decisions**: Run `/deeper-research --lenses=10` with
  all phases, then feed the output into `/design-tournament` for implementation
  exploration. This gives maximum coverage at ~28 total agents.
