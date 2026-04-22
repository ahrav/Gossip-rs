---
name: merge-reviews
description: Consolidate all /review-capture drop files for the current branch into a single verified, deduplicated, conflict-annotated merged plan. Verifies each finding against HEAD (discarding stale ones), merges duplicates across reviewers, flags conflicting suggested fixes, groups findings into execution waves by file ownership, and deletes the individual drop files on success. Run after all parallel review terminals have completed.
---

# merge-reviews

Aggregate N drop files from `/review-capture` into one canonical plan.
Verify findings against HEAD, dedup across reviewers, detect conflicts,
schedule waves, then clean up the drops.

## When to Use

- All review terminals for the current branch have finished capturing.
- Want one consolidated plan before execution.
- Need to detect phantom findings, duplicates, and conflicts before any
  code change.

## When NOT to Use

- Captures still in progress in other terminals. Wait for them.
- Single review with a handful of findings. Execute directly.
- You haven't reviewed yet. Run `/review-capture` first.

## Invocation

```
/merge-reviews
```

No arguments. Operates on the current branch's drop directory.

## Procedure

Follow every step. Do not skip verification or cleanup.

### 1. Locate drop files

```bash
BRANCH=$(git rev-parse --abbrev-ref HEAD)
DROP_DIR=".claude/review-drops/${BRANCH}"
```

If `${DROP_DIR}` doesn't exist or is empty, abort: "No review captures
found for branch <branch>. Run /review-capture first."

List every `*.yaml` in `${DROP_DIR}`. Read all of them into memory.
Parse each envelope.

### 2. Check snapshot consistency

For each drop, compare `head_sha` against current `git rev-parse HEAD`.

- **All drops match current HEAD**: proceed cleanly.
- **Drops span multiple SHAs but all are ancestors of HEAD**: proceed,
  but note drift in the final report per drop.
- **Any drop has a SHA that is NOT an ancestor of HEAD**: something
  destructive happened (rebase, branch reset). Report this to the user
  and ask whether to proceed or abort before continuing.

### 3. Verify every finding against HEAD

For each finding across all drops:

**Anchored findings** (have `file`, `line_start`, `line_end`,
`code_quote`):
1. Confirm `file` exists at HEAD.
2. Read the file and confirm `code_quote` appears at or near the cited
   lines. Allow ±20 lines of drift (code may have moved).
3. If `code_quote` appears elsewhere in the file, update
   `line_start`/`line_end` to the actual location and record a
   `drift_lines` field.
4. If `code_quote` is absent entirely, mark the finding as `STALE`.
5. Ignore whitespace-only differences when comparing.

**Unanchored findings** (benchmarks, design concerns):
- No anchor verification possible. Mark them `UNANCHORED` and pass them
  through to the merged plan as-is. The user decides whether they still
  apply.

**Test-gap findings**: verify the cited file still exists; treat missing
coverage as perpetually valid unless the file was deleted.

Do NOT run `cargo check` or test suites here — verification is a purely
textual check against HEAD. The execute phase runs quality gates.

Produce three buckets: `verified`, `stale`, `unanchored`.

### 4. Deduplicate across reviewers

Group `verified` findings that refer to the same code region:

- Same `file` AND line ranges overlap (within ±5 lines of each other)
  AND claims are semantically similar → candidates for merge.
- Use claim similarity as a tiebreaker: if two findings on the same
  region claim fundamentally different issues (one says "mutex held too
  long", the other says "wrong error variant"), they are not duplicates
  — keep both.

Merge rules:
- Retain the finding with highest severity.
- Combine `suggested_fix` values into a single `suggested_fix` list
  (preserve both if they differ).
- Record `merged_from: [<id1>, <id2>, ...]` on the survivor.
- Record `sources: [<source_slug1>, <source_slug2>, ...]` listing all
  reviewers that flagged this region — a concurrence signal.

### 5. Detect conflicts

For each surviving finding and for each **other** surviving finding on
the same file with overlapping line ranges, check whether
`suggested_fix` values contradict.

Contradictions to flag:
- One says "inline X"; the other says "extract X".
- One says "hold the lock"; the other says "release the lock early".
- One says "add fallible error return"; the other says "make this
  infallible".
- One adds a field/parameter; the other removes it.

Heuristic: read both `suggested_fix` strings and ask "can a single
implementation satisfy both?" If no, flag as a conflict.

Record conflicts as a top-level list in the merged plan:

```yaml
conflicts:
  - region: "src/cache.rs:412-418"
    finding_a: <id>
    finding_b: <id>
    nature: "inline-vs-extract"
    summary: "perf-01 wants inlining; test-07 wants extraction for mocking"
    resolution: null    # user fills this in
```

Do NOT discard conflicting findings. The user resolves them before
execute.

### 6. Schedule execution waves

Group findings by file, then assign each finding a `wave` such that no
two findings in the same wave touch overlapping regions within the same
file.

Algorithm:
- Sort findings by file, then by `line_start`.
- For each file, greedily assign findings to waves: put each finding in
  the earliest wave whose existing findings for this file do not overlap
  with it.
- Findings on different files can share a wave freely.

This matches the parallel-feature-development pattern — waves can be
executed concurrently where file regions don't collide.

### 7. Write the merged plan

Path: `${DROP_DIR}/_merged-<HEAD_SHORT>-<TIMESTAMP>.yaml`

Use a leading underscore so ls-sorting puts it above the per-reviewer
drops, and so a future `/review-capture` won't accidentally treat it as
a reviewer output.

```yaml
merged_at: <ISO-8601 UTC>
merged_from_head: <current HEAD SHA>
branch: <branch>
sources:
  - source_slug: ce-review
    head_sha: <sha>
    findings_total: 12
    findings_verified: 10
    findings_stale: 2
  - source_slug: asm-forge
    ...

summary:
  total_raw_findings: <N>
  verified: <N>
  stale: <N>
  unanchored: <N>
  after_dedup: <N>
  conflicts: <N>
  waves: <N>

stale_findings:
  # Preserved for audit. Not executed.
  - id: <id>
    source_slug: ce-review
    reason: "code_quote not found at file:line and absent from file"
    original: {...}

conflicts:
  - region: "src/cache.rs:412-418"
    finding_a: <id>
    finding_b: <id>
    nature: "..."
    summary: "..."
    resolution: null

waves:
  - wave: 1
    findings:
      - id: <id>
        kind: code_review
        file: ...
        severity: ...
        claim: ...
        suggested_fix: ...
        sources: [ce-review, cache-correctness-review]
        merged_from: [ce-review-003, cache-correctness-review-001]
      - id: <id>
        ...
  - wave: 2
    findings:
      - ...
```

### 8. Cleanup — delete the individual drop files

After the merged plan is written and verified readable, delete every
per-reviewer drop file under `${DROP_DIR}`. Keep only the merged plan
and any other `_merged-*.yaml` files (from prior runs — do not delete
those either, they're history).

```bash
# Delete only the per-reviewer drops, not the merged plans.
for f in "${DROP_DIR}"/*.yaml; do
  base=$(basename "$f")
  case "$base" in
    _merged-*) continue ;;   # keep merged plans
    *) rm -v "$f" ;;
  esac
done
```

Verify with `ls "${DROP_DIR}"` that only `_merged-*.yaml` files remain.

If the merged plan write failed for any reason, do NOT delete anything —
leave all drops in place and report the failure so the user can re-run.

### 9. Report to user

Print a structured summary:

```
Merged <N> drop files into: .claude/review-drops/<branch>/_merged-<sha>-<ts>.yaml

Sources (N reviewers):
  - ce-review            : 12 findings (10 verified, 2 stale)
  - asm-forge            :  5 findings ( 5 verified, 0 stale)
  - cache-correctness    :  8 findings ( 7 verified, 1 stale)

After dedup: 18 findings (4 merges)
Conflicts:    2 — RESOLUTION REQUIRED BEFORE EXECUTE
Waves:        3

Severity:
  critical: 1
  high:     6
  medium:   8
  low:      3

Conflicts requiring your decision:
  1. src/cache.rs:412-418 — perf-01 vs test-07 (inline vs extract)
  2. src/fs_cache_handlers.rs:240-262 — codegen-02 vs correctness-04 (alignment vs layout)

Stale findings (2) preserved in merged plan for audit; not scheduled.

Individual drop files cleaned up: <N> files deleted.

Next: resolve conflicts in the merged plan, then run
/execute-review-findings .claude/review-drops/<branch>/_merged-*.yaml
```

## Rules

### Do NOT execute any findings

This skill produces a plan. It does not write code. If the user asks
"and now execute them" after running `/merge-reviews`, redirect them to
`/execute-review-findings` with the merged plan as input.

### Do NOT delete drops on failure

Cleanup is the last step. If any prior step aborts (consistency failure,
parse error, write failure), leave the drop files untouched. The user
can fix the issue and re-run without losing work.

### Preserve stale findings in the plan

Stale findings are discarded from execution but recorded in
`stale_findings:` with their reason. This is the audit trail that tells
the user which reviewers were working against outdated code.

### Preserve merged plans across runs

Never delete `_merged-*.yaml` files. Each merge run produces a new one.
The directory accumulates history across branches and re-reviews.

### File-region overlap, not file-only

Two findings on `cache.rs` do not conflict if one touches lines 1-50
and the other touches lines 800-820. Only overlapping line ranges
within the same file count.

## Failure modes

- **Drop directory missing**: abort cleanly, recommend `/review-capture`.
- **YAML parse failure on a drop**: isolate the bad file, skip it with
  a warning in the report, continue with the rest. Do NOT delete the
  bad file; the user can inspect.
- **Current HEAD unrelated to drop SHAs**: stop, explain, ask.
- **All findings stale**: still produce a merged plan (with empty
  `waves:`) so the stale-finding audit trail is preserved. The user
  can re-capture against current HEAD.
