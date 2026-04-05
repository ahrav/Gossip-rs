---
name: manage-rules
description: Use for periodic lifecycle maintenance of review rules -- identifies stale rules, noisy rules (FP > 15%), and promotion candidates. Reads review-rules.yaml and review-findings.jsonl to produce an actionable report with user-approved changes.
---

# Manage Rules

Periodic lifecycle maintenance for the review rules in
`.claude/review-rules.yaml`. Identifies stale rules, noisy rules that should
be disabled, and advisory rules ready for promotion to active.

## When to Use

- Weekly or biweekly as part of review system hygiene
- After a batch of reviews when FP rates may have shifted
- When the Stop hook seems to be producing too many false positives
- Before `/detect-patterns` to clean up existing rules first

## Invocation

```
/manage-rules
```

No arguments. The script reads `.claude/review-rules.yaml` and
`.claude/review-findings.jsonl` automatically.

## Workflow

### Step 1: Run the Lifecycle Script

Run the lifecycle analysis script and capture its JSON output:

```bash
bash .claude/scripts/review-rule-lifecycle.sh
```

If the script reports zero rules, inform the user and stop. Suggest running
`/detect-patterns` first to codify some rules.

### Step 2: Present the Lifecycle Report

Display the report as structured sections.

**Rule Inventory:**

```
Active rules:   {active_count}
Advisory rules: {advisory_count}
Disabled rules: {disabled_count}
Overall FP rate: {overall_fp_rate}%
```

**Stale Rules** (active rules with no match in 30+ days):

| Rule ID | Category | Last Matched | Match Count | Created |
|---------|----------|-------------|-------------|---------|

**Noisy Rules** (FP rate > 15%):

| Rule ID | Status | Category | FP Rate | Match Count | FP Count |
|---------|--------|----------|---------|-------------|----------|

**Promotion Candidates** (advisory rules > 7 days old, FP < 15%):

| Rule ID | Category | Created | FP Rate | Match Count |
|---------|----------|---------|---------|-------------|

### Step 3: Handle Stale Rules

For each stale rule, present its details and ask the user:

```
Stale rule: {id}
Category: {category}/{subcategory}
Last matched: {last_matched or "never"}
Match count: {match_count}

Action? [keep / disable / delete]
```

- **keep**: Leave as-is. Update `last_reviewed` timestamp.
- **disable**: Set status to `disabled`. The rule stays in the file but the
  Stop hook ignores it.
- **delete**: Remove the rule entirely from the YAML file.

### Step 4: Handle Noisy Rules

For each noisy rule (FP > 15%), present its details:

```
Noisy rule: {id}
Status: {status}
FP rate: {fp_rate}% ({false_positive_count} FP out of {match_count + false_positive_count} resolved)

Recommend: disable (FP rate exceeds 15% threshold)
Disable this rule? [y/n]
```

If the user confirms, set status to `disabled`. If the user declines, leave
the rule as-is but still update `last_reviewed`.

Do not auto-disable without asking. The user may know the FP rate is
temporarily elevated and prefer to keep the rule.

### Step 5: Handle Promotion Candidates

For each promotion candidate (advisory > 7 days, FP < 15%):

```
Promotion candidate: {id}
Category: {category}/{subcategory}
Created: {created_date} ({days} days ago)
FP rate: {fp_rate}%
Match count: {match_count}

Promote to active? [y/n]
```

If the user confirms, set status to `active`. Active rules produce stronger
output from the Stop hook ("VIOLATION" instead of "note").

### Step 6: Apply Changes

After collecting all user decisions, apply changes to `.claude/review-rules.yaml`.

Use python3 with PyYAML to read, modify, and write the YAML file:

```python
import yaml

with open(".claude/review-rules.yaml", "r") as f:
    data = yaml.safe_load(f)

# Apply status changes, deletions, timestamp updates
# ...

with open(".claude/review-rules.yaml", "w") as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
```

For every rule that was reviewed (regardless of action taken), update:
- `lifecycle.last_reviewed` to today's date (YYYY-MM-DD format)

### Step 7: Summary

Present a summary of all changes made:

```
Rule Lifecycle Review Complete
------------------------------
Rules reviewed:      {total_reviewed}
Stale rules:         {stale_count} ({kept} kept, {disabled} disabled, {deleted} deleted)
Noisy rules:         {noisy_count} ({disabled} disabled, {kept} kept)
Promoted to active:  {promoted_count}
Overall FP rate:     {overall_fp_rate}%
```

## Edge Cases

- **No rules file**: The script handles this and outputs an empty report.
  Inform the user to run `/detect-patterns` first.
- **No findings file**: FP rates are computed from rule lifecycle counters
  instead. The report will still be useful for staleness checks.
- **All rules healthy**: Report a clean bill of health. No action needed.
- **Brand new rules**: Advisory rules less than 7 days old will not appear
  as promotion candidates. This is by design -- the incubation period lets
  FP data accumulate.

## Status Transition Rules

```
  advisory ──(7 days, FP < 15%)──> active
  advisory ──(FP > 15%)──────────> disabled
  active   ──(FP > 15%)──────────> disabled
  active   ──(stale 30 days)─────> user decides: keep / disable / delete
  disabled ──(manual)────────────> advisory  (re-incubation)
```

Rules can only move to `disabled` or be deleted through this skill. Promotion
from `disabled` back to `advisory` requires the user to explicitly edit the
YAML or re-codify via `/detect-patterns`.

## Related Skills

- `/detect-patterns` -- creates new rules from findings patterns
- `/review-dispatch` -- produces findings that feed FP rate calculations
- `/execute-review-findings` -- resolves findings (populates was_true_positive)
