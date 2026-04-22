---
name: review-capture
description: Wrapper skill that invokes any review skill/command and captures its findings into a structured YAML drop file under .claude/review-drops/<branch>/. Use when running parallel code reviews across multiple terminals (each terminal captures one reviewer's output) so a later /merge-reviews pass can dedup, verify, and consolidate before execution. Accepts any target review skill (e.g. ce:review, multi-reviewer-patterns, asm-forge, review-pipeline, perf-pipeline, cache-correctness-review, security-reviewer, etc.).
---

# review-capture

Turn any review skill into a drop-file producer. Delegate to the target
skill fully, then extract its findings into a canonical YAML drop under
`.claude/review-drops/<branch>/` so a later merge phase can consolidate
across all reviewers.

## When to Use

- Running N parallel review terminals, each with a different skill.
- Want a single canonical artifact per review for later aggregation.
- Need a historical record of what a review produced and what HEAD looked
  like at the time.

## When NOT to Use

- Running a single review and fixing immediately. Use the skill directly.
- The target skill mutates code in-band and cannot be run read-only. Do
  not wrap such skills — capture the fixes via git instead.

## Invocation

```
/review-capture <target-skill> [target-args...]
```

Examples:

```
/review-capture ce:review
/review-capture asm-forge src/fs_cache_handlers.rs::read_header
/review-capture perf-pipeline
/review-capture cache-correctness-review
/review-capture review-pipeline --no-execute
```

## Procedure

Follow these steps **in order**. Do not skip steps even if the target
skill produces no findings.

### 1. Resolve drop directory and snapshot HEAD

```bash
BRANCH=$(git rev-parse --abbrev-ref HEAD)
DROP_DIR=".claude/review-drops/${BRANCH}"
mkdir -p "${DROP_DIR}"
HEAD_SHA=$(git rev-parse HEAD)
HEAD_SHORT=$(git rev-parse --short HEAD)
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
# Record for use in step 5 — do not parse these from logs later.
```

If not in a git repo, abort and tell the user. The branch name is the
merge-key — merges are per-branch by design.

### 2. Capture the target identity

- `TARGET_SKILL`: the first arg the user passed (e.g. `ce:review`,
  `asm-forge`, `perf-pipeline`).
- `TARGET_ARGS`: everything after the target-skill name.
- `SOURCE_SLUG`: `TARGET_SKILL` lowercased with `:` and `/` replaced by
  `-` (e.g. `ce:review` → `ce-review`). Used in the output filename.

### 3. Delegate to the target skill

Invoke the target skill via the `Skill` tool. Pass `TARGET_ARGS` as its
args. Let it run to completion — follow its instructions fully, including
any sub-agents, tool calls, or verification steps it performs.

**Rules during delegation:**

- Do NOT short-circuit the target skill's behavior. If it wants to spawn
  6 review sub-agents, let it. If it wants to run benchmarks, let it.
- Do NOT filter the target skill's output. Its full reasoning trail is
  preserved in `target_raw_output` (step 5) for audit.
- Do NOT execute any fixes, even if the target skill suggests them.
  `/review-capture` is capture-only. Execution is a separate phase.
- If the target skill normally both reviews and executes (e.g.
  `review-pipeline`), ask the user whether to pass a `--no-execute` or
  equivalent flag before delegating, or note in the drop file that
  execution steps were skipped.

### 4. Extract findings into the canonical schema

After the target skill completes, read back everything it produced in
this conversation (your own messages containing its output, any tool
results, any sub-agent reports). Extract structured findings using the
schema below.

**Extraction rules:**

- Each discrete finding/observation/recommendation = one entry under
  `findings:`.
- `kind` discriminates the shape — use one of: `code_review`,
  `perf_regression`, `codegen_observation`, `benchmark_result`,
  `design_concern`, `test_gap`, `documentation_gap`, `other`. If none
  fit, use `other` and put everything relevant in `claim` + `details`.
- Preserve file paths, line numbers, function names, and metric
  measurements exactly as the target skill produced them. Do not
  reinterpret or round.
- If the target skill produced prose without clear finding boundaries,
  split on paragraphs or logical units. When in doubt, one finding per
  distinct claim.
- If the target skill produced nothing actionable, still write the drop
  file with `findings: []` — that's a valid capture result.

### 5. Write the drop file

Path: `${DROP_DIR}/${SOURCE_SLUG}-${HEAD_SHORT}-${TIMESTAMP}.yaml`

**Canonical schema:**

```yaml
# Envelope
source_skill: <e.g. ce:review>
source_slug: <e.g. ce-review>
target_args: [<e.g. "src/cache.rs">]
head_sha: <full SHA>
head_short: <short SHA>
branch: <branch name>
captured_at: <ISO-8601 UTC>
captured_by: review-capture
notes: |
  Free-text notes from this capture run — e.g. "target skill asked for
  manual sub-agent intervention, user confirmed X". Empty string if none.

# Full target output preserved verbatim for audit and re-extraction if
# the extracted findings prove incomplete.
target_raw_output: |
  <entire target skill output, with line-leading pipe preserved>

# Structured findings. Each entry MUST have `id`, `kind`, `severity`,
# `claim`. Other fields are kind-specific.
findings:
  - id: <source-slug>-001
    kind: code_review
    severity: critical|high|medium|low|info
    file: src/cache.rs
    line_start: 412
    line_end: 418
    claim: "Holds mutex across clone() of potentially-large Entry"
    code_quote: |
      let guard = self.lock.lock().unwrap();
      let entry = self.map.get(&key).cloned();
      drop(guard);
      entry
    suggested_fix: "Scope the clone inside a block; drop guard before return"
    rationale: "Lock contention spikes under hot-key fanout"

  - id: <source-slug>-002
    kind: perf_regression
    severity: high
    benchmark: cache_io/read_hit
    baseline_ns: 1240
    current_ns: 1580
    delta_pct: 27.4
    significance: "p<0.01"
    suggested_fix: "Investigate the hash re-computation added in HEAD"
    claim: "read_hit regressed 27% vs baseline with high significance"

  - id: <source-slug>-003
    kind: codegen_observation
    severity: medium
    function: fs_cache_handlers::read_header
    file: src/fs_cache_handlers.rs
    line_start: 240
    line_end: 262
    hot_instruction: "ldr x8, [x0, #16]"
    issue: "Unaligned 8-byte load in hot loop"
    suggested_fix: "Reorder struct to align header pointer to 16 bytes"
    claim: "Hot loop contains unaligned load that inhibits vectorization"

  - id: <source-slug>-004
    kind: test_gap
    severity: medium
    file: src/cache.rs
    line_start: 890
    line_end: 905
    claim: "Stale-while-revalidate branch has no test coverage"
    suggested_fix: "Add integration test covering SWR path with upstream timeout"
```

**Field conventions:**

- `severity`: use the target skill's severity verbatim if it assigned
  one. Otherwise infer: critical (data loss, deadlock, security hole),
  high (perf regression > 10%, correctness bug in hot path), medium
  (minor bug, design concern), low (style, naming), info (observation
  only).
- `id`: `<source-slug>-NNN` zero-padded to 3 digits, numbered in the
  order they appear in the target output.
- `file`, `line_start`, `line_end`: only include if the finding is
  anchored to specific code. Omit for benchmark/design-level findings.
- `code_quote`: verbatim copy from HEAD for anchored findings. The merge
  phase uses this to detect stale findings.
- `suggested_fix`: the action the target skill recommends. Omit if the
  finding is informational only.

### 6. Report back

Print a concise summary to the user:

```
Captured <N> findings from <target-skill> at <HEAD_SHORT>
Drop file: .claude/review-drops/<branch>/<filename>.yaml

Severity breakdown: critical=<n> high=<n> medium=<n> low=<n> info=<n>

Other captures in this branch:
  - <existing-drop-file-1>.yaml (<source>, <N> findings)
  - <existing-drop-file-2>.yaml (<source>, <N> findings)

Run /merge-reviews when all review terminals have finished.
```

List sibling drop files so the user knows which reviewers have already
captured.

## Rules

### Do NOT execute fixes

This skill captures. It never modifies code, writes to files outside
`${DROP_DIR}`, or applies fixes. If the target skill attempted to apply
fixes, note it in `notes:` — do not let those fixes land through this
skill.

### Preserve raw output

`target_raw_output` is mandatory. Even when extraction seems complete,
the raw output is the ground truth for audit and for re-extraction if a
future tool version improves parsing.

### SHA at capture time, not at extraction time

`head_sha` reflects HEAD when the capture started, not when extraction
finished. If the user commits mid-run the capture is still a valid
snapshot of the earlier state. The merge phase re-verifies against
current HEAD and flags drift.

### One drop file per invocation

Never append to an existing drop file. Each `/review-capture` invocation
produces exactly one new file. Timestamps in filenames ensure no
collisions between concurrent terminals.

### Do not spawn sub-agents yourself

The target skill may spawn sub-agents as part of its own workflow.
`/review-capture` itself does not spawn any — it runs in the current
conversation, delegates, reads back output, writes one file, exits.

## Failure modes

- **Target skill not found or refused**: report the error, write no
  drop file, exit.
- **Target skill ran but produced no findings**: write the drop file
  with `findings: []` and `notes: "no findings produced"`. This is a
  valid outcome — merge phase will ignore empty drops.
- **Not in a git repo**: abort with a clear message; this skill requires
  a branch for drop directory routing.
- **Extraction ambiguous**: when output is unstructured prose, extract
  conservatively (one finding per distinct claim). Record in `notes:`
  that extraction was best-effort and recommend reviewing
  `target_raw_output` directly.
