---
name: detect-patterns
description: Use when you want to analyze the review findings log for recurring patterns and optionally codify them as review rules. Reads review-findings.jsonl, groups by category, applies the 3+ threshold and FP gate, and presents candidates for user approval.
---

# Detect Patterns

Analyze the review findings log to surface recurring patterns. Patterns that
cross the 3-occurrence threshold with an acceptable false-positive rate are
candidates for codification as review rules.

## When to Use

- Periodically (weekly or after a batch of reviews) to check for emerging patterns
- After a series of `/review-dispatch` or `/review-pipeline` runs
- When you suspect the same category of finding keeps recurring
- Before `/manage-rules` to identify new rule candidates

## Invocation

```
/detect-patterns
```

No arguments. The script reads `.claude/review-findings.jsonl` automatically.

## Workflow

### Step 1: Run the Detection Script

Run the pattern detection script and capture its JSON output:

```bash
bash .claude/scripts/detect-patterns.sh
```

If the script reports an empty findings log, inform the user and stop. There
is nothing to analyze yet.

### Step 2: Present the Pattern Report

Format the JSON output as readable tables for the user.

**Codification candidates** (patterns_detected):

| Category | Subcategory | Count | TP | FP | FP Rate | Recommendation |
|----------|-------------|-------|----|----|---------|---------------|

**Monitoring** (below_threshold):

| Category | Subcategory | Count | Note |
|----------|-------------|-------|------|

**Noisy patterns** (noisy_patterns):

| Category | Subcategory | Count | FP Rate | Note |
|----------|-------------|-------|---------|------|

### Step 3: Show Representative Findings

For each codification candidate, display the representative findings from the
report. These are up to 3 sample findings that illustrate the pattern. Show:
- Finding ID and title
- File and line
- Severity
- Description (truncated if very long)

This gives the user concrete evidence of what the pattern looks like in practice.

### Step 4: Ask for User Approval

Present each codification candidate and ask explicitly:

```
Pattern: {category}/{subcategory} ({count} occurrences, {fp_rate}% FP rate)

Codify this as a review rule? [y/n/skip]
```

**Never auto-codify.** The user must approve each pattern individually.
If the user says "skip", move on without codifying. If the user says "all",
codify all remaining candidates (but still confirm once).

### Step 5: Draft Rule Entries

For each approved pattern, draft a rule entry in the standard format with:

- **id**: derived from category and subcategory (e.g., `mutate-before-confirm`)
- **status**: `advisory` (all new rules start in advisory for 7-day incubation)
- **category** and **subcategory**: from the pattern group
- **severity**: inferred from the most common severity in the findings
- **what**: one-line description of the problematic pattern
- **why**: explanation of the impact and why it matters
- **how**: concrete guidance on the correct approach
- **bad_example**: code snippet showing the problematic pattern (from findings)
- **good_example**: code snippet showing the correct approach
- **scope_dirs**: directories where the pattern was observed
- **detection.semantic_hint**: description for LLM-based semantic checking
- **detection.grep_pattern**: regex for grep-based detection, or null if semantic-only
- **lifecycle**: initialized with current date, zero counters

Show the drafted rule to the user for review before writing. Allow edits.

### Step 6: Write Approved Rules

Append approved rules to `.claude/review-rules.yaml`. If the file does not
exist yet, create it with the `rules:` top-level key.

Read the existing file first to avoid duplicating rule IDs. If a rule with
the same ID already exists, warn the user and ask whether to update or skip.

Use python3 with PyYAML to write valid YAML (do not hand-construct YAML strings):

```python
import yaml
# ... read existing, append new, write back
```

### Step 7: Summary

After all approved rules are written, present a summary:

```
Pattern Detection Complete
--------------------------
Findings analyzed: {total}
Patterns detected: {codify_count} candidates
Rules codified:    {approved_count}
Monitoring:        {below_threshold_count} patterns (< 3 occurrences)
Noisy:             {noisy_count} patterns suppressed (FP > 15%)
```

## Edge Cases

- **No findings file**: The script handles this and outputs an empty report.
  Inform the user that no findings have been logged yet and suggest running
  `/review-dispatch` first.
- **All patterns below threshold**: Report this clearly. The system needs more
  review data before patterns can be codified.
- **All patterns noisy**: This may indicate that resolution data is missing
  (unresolved findings default to FP rate 0). Suggest reviewing and resolving
  existing findings first.
- **Duplicate rule ID**: If a drafted rule ID matches an existing rule, ask
  the user whether to update the existing rule or choose a different ID.

## Related Skills

- `/review-dispatch` -- produces the findings this skill analyzes
- `/execute-review-findings` -- resolves findings (populates resolution data)
- `/manage-rules` -- lifecycle management for existing rules
- `/review-pipeline` -- end-to-end review that also produces findings
