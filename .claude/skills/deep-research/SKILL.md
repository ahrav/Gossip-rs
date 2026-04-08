---
name: deep-research
description: Use when designing safety-critical code, distributed protocols, or novel algorithms where getting the design wrong is expensive. Parallel research agents survey papers, production systems, and prior art, then synthesize into an evidence-backed codebase plan.
---

# Deep Research

A three-phase evidence-gathering workflow for problems where getting the design
wrong is expensive: safety-critical code, performance-critical paths, distributed
systems protocols, unsafe Rust, concurrency primitives, and novel algorithms.

Research agents independently survey the landscape (papers, production systems,
post-mortems, specifications), a synthesizer cross-references and ranks the
evidence, and an integrator maps findings to a concrete implementation plan
grounded in the codebase.

## When to Use

- **Safety-critical**: unsafe blocks, memory management, lock-free data structures
- **Performance-critical**: hot-path algorithms, cache-aware layouts, SIMD strategies
- **Distributed systems**: consensus, replication, failure detection, ordering
- **Novel or unfamiliar territory**: algorithms you haven't implemented before
- **High-stakes design decisions**: choices that are expensive to reverse
- **Concurrency**: lock strategies, atomic ordering, async runtime interactions

## When NOT to Use

- Straightforward CRUD features or wiring code
- Problems with a single obvious solution
- Tasks where you already have deep domain expertise and just need to code
- Use `/design-tournament` instead when the problem is well-understood but
  multiple valid approaches exist

## Invocation

```
/deep-research <problem statement>
```

The `<problem statement>` should describe what you're trying to build or decide,
and why existing knowledge is insufficient. If no argument is given, ask the
user for the problem statement before proceeding.

---

## Pre-Research Setup (Inline)

Before launching Phase 1, the orchestrator (you) performs these steps inline
(not a separate agent):

### Step 0: Establish Current Date

Run `date +%Y-%m-%d` via Bash. Use the returned year for all date-filtered
searches and recency checks. Do NOT assume a year from training data.

### Step 1: Quick Problem Decomposition

Parse the problem statement and identify:
- Core sub-problems (2-3 distinct questions to answer)
- Key search terms and domain-specific vocabulary
- Constraints from the problem statement

### Step 2: Quick Codebase Scan

Use Glob, Grep, and Read to gather:
- Relevant file paths and module structure
- Existing patterns and conventions
- Current approach (if any) to the problem
- Dependencies and their versions

Include a brief summary of this context in every Phase 1 agent's prompt
alongside the problem statement.

---

### Source Credibility Tiers

Agents should weight evidence by domain credibility alongside evidence strength.
Higher-credibility domains require less corroboration; lower ones need more.

| Tier | Score | Domains | Treatment |
|------|-------|---------|-----------|
| **High** (80-100) | Auto-trust for factual claims | arxiv.org, usenix.org, dl.acm.org, ieee.org, nature.com, official project docs, RFC specs | Core evidence; cite directly |
| **Moderate** (60-79) | Trust with corroboration | Engineering blogs (Cloudflare, AWS, Datadog, Discord), conference talks, arstechnica | Good lead; corroborate with another source |
| **Low** (40-59) | Leads only | Medium posts, personal blogs, Stack Overflow, forum discussions, unknown domains | Use only when nothing stronger exists; flag as WEAK |
| **Suspect** (<40) | Verify before citing | Content farms, SEO-optimized listicles, anonymous posts, sensational patterns | Do NOT cite unless verified against primary source |

### Anti-Hallucination Protocol

These rules apply to ALL agents across ALL phases. Violation makes findings
worthless.

1. **Source grounding**: Every factual claim MUST cite a concrete source (URL,
   paper, system). Unsourced claims must be explicitly labeled as inference.
2. **Distinguish facts from synthesis**: Use "According to [source]..." for
   sourced facts. Use "This suggests..." for synthesis.
3. **No vague attributions**: NEVER write "research suggests...", "studies
   show...", or "experts believe..." without a specific citation.
4. **Admit uncertainty**: If no sources address a question, write "No sources
   found for X" — do NOT fabricate a reference.
5. **Label speculation**: Any inference beyond what sources explicitly state
   must be marked as such.
6. **Verify before citing**: If uncertain whether a source says X, do NOT
   cite it. Note the uncertainty instead.
7. **Watch for hallucination patterns**: Generic academic titles without a real
   URL, future publication dates, or anachronistic terms (AI/LLM terminology
   in pre-2015 citations) are red flags.

---

## Phase 1 — Research (3-5 Parallel Agents)

Launch **5 research agents in parallel** using the Task tool with
`subagent_type=general-purpose`. Each agent has a distinct research lens but
receives the same problem statement. All agents explore the codebase for context
AND search the web for external evidence.

**All 5 agents MUST be launched in a single message** (one message, five Task
tool calls) so they run concurrently.

### Research Agent Specialties

Each agent receives the common preamble below, with `{PROBLEM}` replaced by
the user's problem statement, `{AGENT_ID}` set to its label, and
`{SPECIALTY}` / `{FOCUS}` set per-agent.

---

#### Common Preamble (included in every agent's prompt)

```
You are Research Agent {AGENT_ID} — a {SPECIALTY} specialist.

## Problem Under Investigation
{PROBLEM}

## Current Date
{CURRENT_DATE}

Use this date for all recency checks and date-filtered searches. Do NOT assume
a year from training data.

## Codebase Context
{CODEBASE_CONTEXT}

## Your Research Mission

You are one of 5 independent research agents. Your job is to gather HARD
EVIDENCE — not opinions — about how this problem has been solved before.
Every claim must have a source. Unsourced claims are worthless.

### Research Process

1. **Understand the codebase context**: Use Glob, Grep, and Read to understand
   the relevant parts of the codebase. What exists today? What constraints does
   the current architecture impose?

2. **Search for external evidence**: Use WebSearch and WebFetch to find:
   - Academic papers and technical reports
   - Documentation from production systems that solve similar problems
   - RFCs, specifications, and formal descriptions
   - Post-mortems and failure analyses
   - Conference talks, technical blog posts from credible sources
   - Existing open-source implementations

   Launch ALL searches in parallel when possible (single message, multiple
   tool calls). Follow promising results with targeted WebFetch deep-dives.

3. **Evaluate and document**: For each piece of evidence, record:
   - Source (URL, paper title, system name)
   - Key finding or technique
   - Relevance to our specific problem
   - Evidence strength (see scale below)
   - Source credibility tier (see below)

### Evidence Strength Scale

| Level | Label | Description | Example |
|-------|-------|-------------|---------|
| 5 | **Proven at scale** | Battle-tested in production systems handling similar workloads | FoundationDB's simulation testing, TigerBeetle's storage engine |
| 4 | **Peer-reviewed** | Published in reputable venue with formal analysis | OSDI/SOSP paper with proofs |
| 3 | **Implemented & tested** | Open-source implementation with benchmarks/tests | Well-maintained crate with >1k stars, comprehensive test suite |
| 2 | **Documented practice** | Technical blog from credible engineering org | Blog post from Cloudflare, Datadog, AWS engineering |
| 1 | **Anecdotal** | Forum discussion, personal blog, Stack Overflow answer | Useful for leads but needs corroboration |

### Source Credibility Tiers

| Tier | Domains | Treatment |
|------|---------|-----------|
| High (80-100) | arxiv.org, usenix.org, dl.acm.org, ieee.org, official docs, RFCs | Core evidence; cite directly |
| Moderate (60-79) | Engineering blogs (Cloudflare, AWS, Datadog), conf talks, arstechnica | Corroborate with another source |
| Low (40-59) | Medium posts, personal blogs, SO, forum discussions | Flag as WEAK; use only if nothing stronger exists |
| Suspect (<40) | Content farms, SEO listicles, anonymous posts | Do NOT cite unless verified against primary source |

### Anti-Hallucination Rules

- NEVER fabricate a citation. If no sources address a question, say so.
- Distinguish FACTS (from sources: "According to [source]...") from SYNTHESIS
  (your analysis: "This suggests...").
- No vague attributions: NEVER write "research suggests" or "studies show"
  without a specific citation.
- Watch for hallucination patterns: generic academic titles without real URLs,
  future publication dates, pre-2015 citations mentioning LLMs/transformers.
- When uncertain whether a source says X, note the uncertainty — do not cite.

### Focus Area
{FOCUS}

### Rules

- EVERY finding must have a concrete source. No source = don't include it.
- Prefer primary sources over secondary summaries.
- If you find contradictory evidence, report BOTH sides with sources.
- Distinguish between "X is theoretically optimal" and "X works in production."
- Note when evidence is from a different domain and may not transfer directly.
- Search for COUNTER-evidence too — what are the failure modes of popular approaches?
- If a search returns no useful results, say so. Do not fabricate references.
- Aim for source diversity: mix academic, production, and practitioner sources.

### Output Format

Return a markdown document starting with:
`# Research Report — Agent {AGENT_ID}: {SPECIALTY}`

Then these sections:

#### 1. Codebase Context
What you found in the current codebase that's relevant. File paths and line
numbers for key structures.

#### 2. Findings
For each piece of evidence (aim for 5-15 findings):

**Finding {N}: {title}**
- **Source**: {URL or citation}
- **Source credibility**: {High/Moderate/Low} — {domain}
- **Evidence strength**: {1-5} — {label}
- **Summary**: {2-4 sentences}
- **Key technique/insight**: {the actionable takeaway}
- **Applicability to our problem**: {high/medium/low} — {why}
- **Caveats**: {limitations, different assumptions, scaling concerns}

#### 3. Structured Evidence Summary
After all findings, provide a machine-readable summary for synthesis:

```json
[
  {
    "id": "F1",
    "claim": "specific claim text",
    "source_url": "https://...",
    "source_title": "...",
    "evidence_strength": 4,
    "credibility_tier": "high",
    "applicability": "high"
  }
]
```

This structured summary prevents synthesis fatigue when merging results from
5 agents. Include it AFTER the narrative findings, not instead of them.

#### 4. Patterns & Consensus
What approaches appear repeatedly across sources? Where do experts agree?

#### 5. Disagreements & Open Questions
Where do sources contradict each other? What remains unresolved?

#### 6. Recommended Reading
Top 3-5 sources the team should read, ranked by relevance.
```

---

#### Agent 1 — Foundational Theory

```
{SPECIALTY}: Foundational Theory & Algorithms
{FOCUS}:
Search for the THEORETICAL foundations of this problem:
- Seminal papers and algorithms (Lamport, Dijkstra, Knuth, etc.)
- Formal correctness proofs or verification approaches
- Complexity bounds — what's provably optimal?
- Mathematical models and invariants
- Type-theoretic or formal methods approaches

Start with WebSearch queries like:
- "{problem keywords} algorithm formal proof"
- "{problem keywords} paper OSDI SOSP VLDB SIGMOD"
- "{problem keywords} correctness verification"
- "{problem keywords} complexity bounds"

Look at:
- arxiv.org, dl.acm.org, usenix.org proceedings
- PhD theses and technical reports
- Textbook chapters (CLRS, TAOCP, etc.)
```

---

#### Agent 2 — Production Systems

```
{SPECIALTY}: Production Systems & Battle-Tested Implementations
{FOCUS}:
Search for how REAL SYSTEMS in production solve this problem:
- Database engines (FoundationDB, TigerBeetle, CockroachDB, SQLite, DuckDB)
- Storage systems (RocksDB, LevelDB, WiscKey)
- Distributed systems (etcd, Raft implementations, Paxos variants)
- High-performance systems (DPDK, SPDK, io_uring users)
- Language runtimes (Go GC, Rust allocators, JVM internals)
- Operating systems (Linux kernel, FreeBSD, Fuchsia)

Start with WebSearch queries like:
- "{problem keywords} implementation production"
- "{system name} {problem keywords} design"
- "{problem keywords} source code github"
- "how does {system} handle {problem}"

For each system found:
- What approach do they use?
- What scale does it operate at?
- What trade-offs did they make and why?
- Link to source code or design docs when available.
```

---

#### Agent 3 — Failure Modes & Pitfalls

```
{SPECIALTY}: Failure Modes, Post-Mortems & Anti-Patterns
{FOCUS}:
Search for how this problem GOES WRONG:
- Post-mortems from outages caused by similar systems
- CVEs and security advisories in related implementations
- Known anti-patterns and common mistakes
- Performance cliffs and degenerate cases
- Subtle bugs found in production (Jepsen reports, fuzzing results)
- Memory safety issues in similar C/C++/Rust implementations

Start with WebSearch queries like:
- "{problem keywords} bug post-mortem"
- "{problem keywords} vulnerability CVE"
- "{problem keywords} performance regression"
- "{problem keywords} Jepsen analysis"
- "{problem keywords} common mistakes pitfalls"
- "{problem keywords} undefined behavior unsafe"

For each failure found:
- What went wrong?
- Root cause analysis
- How was it detected?
- How was it fixed or mitigated?
- What invariant was violated?
```

---

#### Agent 4 — Rust Ecosystem & Implementation Patterns

```
{SPECIALTY}: Rust Ecosystem & Implementation Patterns
{FOCUS}:
Search for how this problem is solved IN RUST specifically:
- Existing crates that address this problem (crates.io, lib.rs)
- Rust-specific patterns (ownership for safety, typestate, const generics)
- Unsafe code patterns and safety proofs in similar Rust projects
- Benchmarks comparing Rust implementations
- Rust RFCs and compiler internals if relevant

Start with WebSearch queries like:
- "{problem keywords} rust crate"
- "{problem keywords} rust implementation"
- "{problem keywords} rust unsafe safe abstraction"
- "{problem keywords} rust performance benchmark"
- "crates.io {problem keywords}"

For each crate or pattern found:
- API design — how is it exposed to users?
- Safety story — how is unsafe (if any) encapsulated?
- Performance characteristics — any benchmarks?
- Maintenance status — actively maintained? Production users?
- Code quality — tests, docs, CI, fuzzing?

Also check the Rust standard library and popular foundational crates
(crossbeam, tokio, rayon, parking_lot, etc.) for relevant patterns.
```

---

#### Agent 5 — Industry Practice & Architecture

```
{SPECIALTY}: Industry Practice & System Architecture
{FOCUS}:
Search for how ENGINEERING ORGANIZATIONS approach this problem:
- Technical blog posts from major engineering orgs (Google, Meta, AWS,
  Cloudflare, Datadog, Discord, Figma, Fly.io)
- Conference talks (Strange Loop, RustConf, P99 CONF, QCon)
- Architecture Decision Records (ADRs) in open-source projects
- RFCs and design documents from relevant projects
- Books and practitioner guides

Start with WebSearch queries like:
- "{problem keywords} engineering blog"
- "{problem keywords} architecture design document"
- "{problem keywords} conference talk"
- "{problem keywords} RFC design"
- "{problem keywords} lessons learned"
- "{problem keywords} at scale"

For each practice found:
- What organization or project uses this approach?
- At what scale?
- What alternatives did they evaluate?
- What would they do differently in hindsight?
- Is this approach specific to their constraints or generalizable?
```

---

### Collecting Results

After all 5 agents complete, gather their outputs. If any agent fails or times
out, proceed with the agents that succeeded (minimum 3 required for Phase 2).

---

## Phase 2 — Synthesize (Single Agent)

Launch **1 synthesis agent** using the Task tool with
`subagent_type=general-purpose`.

### Synthesizer Prompt

```
You are the Research Synthesizer. Five independent research agents have
investigated the same problem from different angles. Your job is to
cross-reference their findings into a single, evidence-ranked knowledge base.

## Original Problem
{PROBLEM}

## Research Reports
{ALL_FIVE_REPORTS}

## Your Task

### 1. Evidence Inventory

Create a master list of ALL unique findings across all 5 agents. For
findings reported by multiple agents, merge them and note corroboration.

Use the structured evidence summaries (JSON blocks) from each agent to
bootstrap the inventory, then enrich from the narrative findings.

For each finding:
- **ID**: F{N}
- **Title**: {descriptive title}
- **Sources**: {all sources citing this finding, with URLs}
- **Corroboration**: {how many agents independently found this}
- **Evidence strength**: {1-5, use the highest-quality source}
- **Source credibility**: {High/Moderate/Low — from the best source}
- **Applicability**: {high/medium/low for our specific problem}
- **Weighted score**: {evidence_strength × credibility_multiplier × corroboration_count}

Credibility multipliers: High=1.0, Moderate=0.8, Low=0.5, Suspect=0.1.

### 2. Hallucination Check

Review all findings for hallucination indicators:
- Citations with generic academic titles but no working URL
- Future publication dates or anachronistic terminology
- Findings that appear in only one agent with no external corroboration and
  evidence strength >= 3 (suspiciously high confidence from a single source)
- Metadata mismatches (title says one thing, linked content says another)

Flag any suspicious findings with: "HALLUCINATION RISK: {reason}".
Downgrade their evidence strength to 0 and exclude from the ranking.

### 3. Consensus Matrix

Identify the key design decisions for this problem, then for each decision
show where the evidence points:

| Decision | Option A | Option B | Evidence For A | Evidence For B | Verdict |
|----------|----------|----------|----------------|----------------|---------|

The verdict should be: STRONG CONSENSUS, LEAN (direction), CONTESTED, or
INSUFFICIENT EVIDENCE.

### 4. Evidence-Ranked Techniques

Rank all discovered techniques/approaches by weighted evidence score:

Score = (evidence_strength × credibility_multiplier × applicability × corroboration_count)

| Rank | Technique | Score | Evidence | Credibility | Applicability | Corroboration | Key Source |
|------|-----------|-------|----------|-------------|---------------|---------------|------------|

### 5. Risk Register

From the failure modes research, compile a risk register:

| Risk ID | Risk | Likelihood | Impact | Mitigation | Source |
|---------|------|------------|--------|------------|--------|

### 6. Contradictions & Gaps

- Where do sources disagree? What's the strongest evidence on each side?
- What aspects of the problem have NO evidence? Where are we flying blind?
- What evidence exists but doesn't transfer to our specific context?

For each critical gap, provide:
- **Gap**: {description}
- **Impact**: {how this gap affects design decisions}
- **Suggested delta-queries**: {2-3 specific search queries that might fill it}

### 7. Key Insights

The 5-10 most important things learned from this research that should
directly influence the design. Each must cite at least one source.

### Rules

- Do NOT add your own findings — you are synthesizing, not researching.
- If an agent's finding has no source, downgrade it to evidence strength 0
  and flag it as UNVERIFIED.
- Preserve ALL source URLs from the original reports.
- If agents contradict each other, present both sides — do not pick a winner
  unless the evidence clearly favors one side.
- Be explicit about what we DON'T know, not just what we do.

### Output Format

Return a markdown document starting with:
`# Research Synthesis`

Include all sections above, plus a final section:

#### Executive Summary
3-5 bullet points capturing the most critical findings for someone who
won't read the full report.
```

### Gap-Triggered Delta-Queries (Between Phase 2 and Phase 3)

After Phase 2 completes, the orchestrator (you) reviews the Contradictions &
Gaps section. If the synthesis identifies a **critical gap** — a question that
load-bearing design decisions depend on but has no evidence — trigger targeted
retrieval before proceeding to Phase 3.

**Trigger criteria**: A gap is critical when removing it would change the
#1 or #2 ranked technique, or when INSUFFICIENT EVIDENCE appears in the
Consensus Matrix for a fundamental design decision.

**Process**:
1. Formulate 2-4 narrow, specific WebSearch queries from the synthesizer's
   suggested delta-queries.
2. Launch all queries in parallel (single message).
3. Time-box to 3 minutes total.
4. Append results to the synthesis as a "Supplementary Evidence" section
   before passing to Phase 3.
5. Maximum 1 delta-query round per research run.

---

## Phase 3 — Integrate (Single Agent)

Launch **1 integration agent** using the Task tool with
`subagent_type=general-purpose`.

This agent maps the synthesized research to a concrete implementation plan
grounded in the actual codebase.

### Integrator Prompt

```
You are the Research-to-Plan Integrator. You have a comprehensive research
synthesis and access to the codebase. Your job is to produce a concrete,
evidence-backed implementation plan.

## Original Problem
{PROBLEM}

## Research Synthesis
{SYNTHESIS_REPORT}

## Your Task

### Step 1: Codebase Mapping

Thoroughly explore the codebase to understand:
- Current architecture and module structure (use Glob, Grep, Read)
- Existing patterns and conventions
- What infrastructure already exists that can be leveraged
- What constraints the current architecture imposes
- Dependencies and their versions

Map each research finding to specific locations in the codebase:
- Which files/modules would be affected?
- What existing abstractions can be reused?
- Where do new abstractions need to be introduced?

### Step 2: Evidence Triage

Before planning, review the synthesis for:
- **Hallucination-flagged findings**: Do NOT base any design decision on findings
  flagged as HALLUCINATION RISK. If a key decision depends on such a finding,
  note it as UNJUSTIFIED and flag for additional research.
- **Low-credibility findings**: Findings sourced only from Low/Suspect credibility
  tiers should not be the sole basis for a design decision. Note them as
  requiring corroboration.
- **Unresolved gaps**: If delta-queries were run, incorporate their results.
  If gaps remain, note them as explicit risks.

### Step 3: Implementation Plan

Produce a step-by-step implementation plan where EVERY design decision
cites evidence from the synthesis:

#### Plan Format

For each step:

**Step {N}: {title}**
- **What**: {concrete description — types, signatures, module placement}
- **Why**: {justification citing specific findings by ID: F1, F7, etc.}
- **Evidence**: {the specific technique/paper/system this is based on}
- **Evidence quality**: {evidence strength + credibility tier of the key source}
- **Files**: {exact file paths to create or modify}
- **Risks**: {from the risk register, with mitigation}
- **Acceptance criteria**: {how to verify this step is correct}

### Step 4: Evidence Trail

Create a traceability matrix:

| Plan Step | Research Finding(s) | Evidence Strength | Credibility | Confidence |
|-----------|--------------------|--------------------|-------------|------------|

Confidence levels:
- HIGH: Multiple strong sources agree, directly applicable, High credibility
- MEDIUM: Evidence exists but from different context, or sources disagree
- LOW: Limited evidence, based on extrapolation, or Low credibility sources only
- NOVEL: No direct evidence found — this is our own design (flag for extra review)

Any step with LOW or NOVEL confidence gets a mandatory note explaining
what additional validation is needed (benchmarks, property tests, fuzzing,
formal verification, etc.).

### Step 5: Alternative Approaches

For any CONTESTED decisions from the synthesis, describe:
- The alternative approach
- What evidence supports it
- Under what conditions we'd switch to it
- How to structure the code so switching is feasible

### Step 6: Validation Strategy

How to verify the implementation is correct:
- What properties should be tested (unit, property-based, fuzz)?
- What benchmarks should be run?
- What failure modes from the risk register need explicit test cases?
- Are there formal verification opportunities (Kani, MIRI)?

### Rules

- Every design decision MUST cite evidence. If there's no evidence for a
  choice, flag it explicitly as NOVEL/UNJUSTIFIED.
- NEVER base a decision on a hallucination-flagged finding.
- Be concrete: file paths, type signatures, function names. Not hand-waving.
- Respect existing codebase conventions — don't propose patterns alien to
  the project.
- The plan should be implementable by a developer who hasn't read the full
  research — include enough context in each step.
- Include estimated complexity per step (S/M/L) but NOT time estimates.

### Output Format

Return a markdown document starting with:
`# Implementation Plan`

Include all sections above, plus:

#### References
A numbered bibliography of all sources cited in the plan, with URLs.
Each citation in the plan body should reference this list: [1], [2], etc.
```

---

## Final Output Format

After the integrator completes, present the combined output to the user:

```markdown
## Deep Research Results

### Problem
{one-line restatement}

### Current Date
{YYYY-MM-DD used for all recency checks}

### Executive Summary
{from the synthesizer's executive summary}

### Evidence Highlights
| # | Finding | Evidence Strength | Credibility | Sources | Applicability |
|---|---------|-------------------|-------------|---------|---------------|
{top 10 findings from the synthesis, ranked by weighted score}

### Hallucination Flags
{any findings flagged as HALLUCINATION RISK by the synthesizer, with reasons}
{if none: "No hallucination indicators detected."}

### Implementation Plan
{the integrator's full plan}

### Consensus & Contested Decisions
{consensus matrix from the synthesis}

### Risk Register
{risk register from the synthesis}

### Delta-Query Results
{if gap-triggered delta-queries were run: summarize what was found}
{if not triggered: "No critical gaps required additional retrieval."}

### Full Research (collapsed)
<details><summary>Research Agent 1: Foundational Theory</summary>
{full report}
</details>
<details><summary>Research Agent 2: Production Systems</summary>
{full report}
</details>
<details><summary>Research Agent 3: Failure Modes & Pitfalls</summary>
{full report}
</details>
<details><summary>Research Agent 4: Rust Ecosystem</summary>
{full report}
</details>
<details><summary>Research Agent 5: Industry Practice</summary>
{full report}
</details>
<details><summary>Full Research Synthesis</summary>
{synthesis report}
</details>

### References
{consolidated bibliography from integrator}
```

---

## Quality Gate Checks

These standards apply to the output from each phase. The orchestrator (you)
verifies them before proceeding to the next phase.

### Phase 1 Agent Output Quality

- [ ] At least 5 findings per agent (fewer only if the agent explicitly states
      "exhaustive search yielded N results")
- [ ] Every finding has a Source field with a real URL or citation
- [ ] Structured evidence summary (JSON block) is present
- [ ] No finding uses ONLY evidence strength 1-2 without flagging as WEAK

### Phase 2 Synthesis Quality

- [ ] Evidence Inventory covers ALL Phase 1 agents (none silently dropped)
- [ ] Consensus Matrix has at least 3 decision points
- [ ] Risk Register has at least 3 entries
- [ ] Hallucination check section is present (even if no flags)
- [ ] Every merged finding preserves original source URLs

### Phase 3 Integration Quality

- [ ] Every plan step cites finding IDs (steps without citations are unjustified)
- [ ] Evidence Trail has no NOVEL entries without explicit justification
- [ ] Acceptance criteria are verifiable, not vague ("it works")
- [ ] No plan step is based on a hallucination-flagged finding

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

For long research runs, persist intermediate results to survive context
compaction.

### What to Persist

After Phase 2 completes, write a summary file:

```
.claude/research-state/{run-id}/
  phase1-summary.md   — Concatenated Phase 1 agent reports
  phase2-synthesis.md  — Phase 2 output (+ any delta-query supplements)
  phase3-plan.md       — Phase 3 implementation plan
```

### When to Persist

- **Always persist** after Phase 2 (the synthesis is the most expensive to
  recreate from 5 agents).
- **Persist the final output** (Phase 3) always.

### Run ID

Use a stable identifier: `{date}-{first-5-words-of-problem-slugified}`.
Example: `2026-04-08-lock-free-queue-design`.

---

## Configuration

Default: 5 researchers + 1 synthesizer + 1 integrator (7 total agents).

The user can reduce the research agents:
```
/deep-research 3 agents: <problem>
```

Enforce these limits:
- Phase 1: minimum 3 research agents, maximum 5
- If 3 agents: use agents 1 (Theory), 2 (Production Systems), 3 (Failure Modes)
- If 4 agents: add agent 4 (Rust Ecosystem)
- If 5 agents: all five (default)
- Phase 2: always exactly 1 synthesizer
- Phase 3: always exactly 1 integrator

## Tips

- Include relevant file paths or module names in the problem statement so
  research agents can examine the codebase for context.
- For distributed systems problems, the Failure Modes agent (Agent 3) is
  critical — never reduce below 3 agents.
- The output from this skill feeds naturally into `/design-tournament` if you
  want to explore multiple implementation approaches after research.
- For unsafe Rust, the Rust Ecosystem agent (Agent 4) is essential for finding
  established safe abstraction patterns.
- Research quality depends on search query quality. The agents will try multiple
  queries but the problem statement should include domain-specific terminology
  to improve results.
