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

### Source Credibility Tiers

Agents should weight evidence by domain credibility alongside evidence strength.
Higher-credibility domains require less corroboration; lower ones require more.

| Tier | Score | Domains | Treatment |
|------|-------|---------|-----------|
| **High** (80-100) | Auto-trust for factual claims | arxiv.org, usenix.org, dl.acm.org, ieee.org, nature.com, official project docs, RFC specs | Core evidence; cite directly |
| **Moderate** (60-79) | Trust with corroboration | Engineering blogs (Cloudflare, AWS, Datadog, Discord), conference talks, well-known tech media (arstechnica) | Good lead; corroborate with another source |
| **Low** (40-59) | Leads only | Medium posts, personal blogs, Stack Overflow, forum discussions, unknown domains | Use only when nothing stronger exists; flag as WEAK |
| **Suspect** (<40) | Verify before citing | Content farms, SEO-optimized listicles, anonymous posts, domains with sensational patterns | Do NOT cite unless verified against primary source |

When scoring evidence, the final weight is:
`weight = evidence_strength × credibility_tier_multiplier × corroboration_count`

Where credibility multiplier: High=1.0, Moderate=0.8, Low=0.5, Suspect=0.1.

### Anti-Hallucination Protocol

These rules apply to ALL agents across ALL phases. Violation makes findings
worthless.

1. **Source grounding**: Every factual claim MUST cite a concrete source (URL,
   paper, system). Unsourced claims must be explicitly labeled as inference.
2. **Distinguish facts from synthesis**: Use "According to [source]..." for
   sourced facts. Use "This suggests..." or "Based on the evidence, we infer..."
   for synthesis.
3. **No vague attributions**: NEVER write "research suggests...", "studies
   show...", or "experts believe..." without a specific citation.
4. **Admit uncertainty**: If no sources address a question, write "No sources
   found for X" — do NOT fabricate a reference.
5. **Label speculation**: Any inference beyond what sources explicitly state
   must be marked: "This is an inference from [finding IDs], not directly
   sourced."
6. **Verify before citing**: If uncertain whether a source says X, do NOT
   cite it. Note the uncertainty instead.
7. **Watch for hallucination patterns**: Generic academic titles like "A
   Comprehensive Survey of..." without a real URL, future publication dates,
   or anachronistic terms (AI/LLM terminology in pre-2015 citations) are red
   flags.

---

## Orchestrator: Problem Decomposition (Inline)

Before launching Phase 1, the orchestrator (you) produces a **Structured
Research Brief**. This is NOT a separate agent — do this inline.

### Steps

0. **Establish current date**: Run `date +%Y-%m-%d` via Bash to get today's
   date. Use this year for all date-filtered searches and recency checks. Do
   NOT assume a year from training data.

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

### Current Date
{YYYY-MM-DD from Step 0 — agents use this for recency filtering}

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

## Adaptive Scope Refinement (Between Phase 2 and Phases 3/4)

After Phase 2 synthesizes Phase 1 findings, **before launching Phases 3 and 4**,
the orchestrator (you) evaluates whether the research scope needs adjustment.

### When to Refine

Refinement is triggered when ANY of these signals appear in Phase 2's output:

- Major findings contradict the original problem framing
- A critical sub-problem emerged that wasn't in the Research Brief
- Evidence reveals a more important angle than originally scoped
- Sources consistently discuss aspects not in the initial Research Brief
- A sub-problem has INSUFFICIENT EVIDENCE and needs different search terms

### Refinement Process

1. **Compare** the Research Brief's Sub-Problems against Phase 2's findings:
   - Which sub-problems have strong evidence?
   - Which have gaps?
   - What new sub-problems emerged?

2. **Update the Research Brief** (inline, not a new agent):
   - Add new sub-problems discovered during Phase 1
   - Demote sub-problems with abundant evidence (they're answered)
   - Adjust search terms based on terminology Phase 1 agents discovered
   - Note any constraints that turned out to be wrong

3. **Adjust Phase 3 deep-dive targets**: Phase 2 already identifies these, but
   the orchestrator can reorder or replace targets based on the updated brief.

4. **Optional targeted gap-fill**: If refinement reveals a *critical* gap that
   Phase 1 missed entirely (not just underexplored — missed), launch 1-2
   targeted WebSearch calls before Phase 3/4. Time-box to 2 minutes.

### Rules

- Refinement must be evidence-driven (cite Phase 2 findings, not speculation).
- No more than 30% change to scope — if more is needed, the original problem
  statement was under-specified.
- Preserve the original research question's core intent.
- Document what changed and why in the final output.

---

## Critique Loop-Back (Phase 4 → Retrieval)

If Phase 4 adversarial agents identify a **critical knowledge gap** — not a
writing or framing issue, but a factual gap where the design would be built on
unverified assumptions — the orchestrator triggers a targeted retrieval loop
before proceeding to Phase 5.

### Trigger Criteria

Loop-back fires when ANY adversarial agent reports:
- A top-3 ranked approach has no counter-evidence search results (Contrarian
  Searcher found nothing — suspicious, not reassuring)
- Cross-Validator rates 2+ load-bearing claims as UNVERIFIABLE
- Assumptions Auditor flags a HIGH-RISK assumption with no verification path
- Devil's Advocate constructs a >70% confidence counter-argument

### Loop-Back Process

1. Formulate 2-4 **delta-queries**: narrow, specific searches designed to fill
   the exact gap (not broad re-research).
2. Launch delta-queries via WebSearch (parallel, single message).
3. Time-box to 3 minutes total.
4. Append delta-query results to Phase 4 output as a "Supplementary Evidence"
   section before feeding into Phase 5.
5. Maximum 1 loop-back per research run. If the gap persists after loop-back,
   it becomes an explicit "Unresolved Risk" in the final output.

---

## Quality Gate Checks

These standards apply to the final output from each phase. The orchestrator
(you) verifies them before proceeding to the next phase.

### Phase 1 Agent Output Quality

- [ ] At least 5 findings per agent (fewer is acceptable only if the agent
      explicitly states "exhaustive search yielded N results")
- [ ] Every finding has a Source field with a real URL or citation
- [ ] No finding uses ONLY evidence strength 1-2 without flagging as WEAK
- [ ] Output is within budget (~3000 tokens)

### Phase 2 Synthesis Quality

- [ ] Evidence Inventory covers ALL Phase 1 agents (none silently dropped)
- [ ] Consensus Matrix has at least 3 decision points
- [ ] Deep-Dive Targets section has 3-5 specific, actionable questions
- [ ] Risk Register has at least 3 entries
- [ ] Every merged finding preserves original finding IDs

### Phase 5 Final Synthesis Quality

- [ ] Reconciliation table covers every S1.F* finding
- [ ] Adversarial impacts are honestly reflected (not dismissed or minimized)
- [ ] Updated ranking differs from Phase 2 ranking (adversarial evidence
      should change something, even if minor)
- [ ] At least one finding is DOWNGRADED or REVISED (if none are, adversarial
      review was too weak or synthesis is ignoring challenges)

### Phase 6 Integration Quality

- [ ] Every plan step cites finding IDs (steps without citations are unjustified)
- [ ] At least one step addresses an adversarial concern directly
- [ ] Traceability matrix has no NOVEL entries without explicit justification
- [ ] Acceptance criteria are verifiable, not vague ("it works")

### Writing Standards (All Phases)

- **Precision**: Exact numbers over vague qualifiers. "23% faster" not
  "significantly faster". "5 RCTs (n=1,847)" not "several studies".
- **Economy**: No fluff words. Every sentence carries information.
- **Directness**: State conclusions without hedging unless uncertainty is
  genuine. "Binary search is optimal here" not "It might be the case that
  binary search could potentially be considered".
- **Prose-first**: Findings and synthesis should be >=80% flowing prose.
  Bullets only for distinct enumerable lists (API names, file paths, etc.).

---

## Intermediate Persistence

For long research runs, intermediate results should be persisted to disk to
survive context compaction.

### What to Persist

After each phase completes, write a summary file:

```
.claude/research-state/{run-id}/
  brief.md          — Research Brief (after Orchestrator)
  phase1-summary.md — Concatenated Phase 1 agent reports
  phase2-synthesis.md — Phase 2 output
  phase3-dives.md   — Concatenated Phase 3 deep-dive reports
  phase4-adversarial.md — Concatenated Phase 4 reports
  phase5-final.md   — Phase 5 final synthesis
  phase6-plan.md    — Phase 6 implementation plan
```

### When to Persist

- **Always persist** after Phase 2 (the synthesis is the most expensive to
  recreate).
- **Persist after Phase 4** if >8 agents were used in Phase 1 (large context).
- **Persist the final output** (Phase 6) always.

### Run ID

Use a stable identifier: `{date}-{first-5-words-of-problem-slugified}`.
Example: `2026-04-08-gossip-protocol-partition-tolerance`.

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
