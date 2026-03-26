---
name: run-runbook
description: Use when the user wants to launch a runbook, run an audit, review, or analysis task via Jetty, or says "run the X runbook". Also triggers on "launch runbook", "execute runbook", "run dedup-audit", "run security-reviewer", or any request to run a task from runbooks/.
---

# Run Runbook

Launch runbooks from `runbooks/` via Jetty using `run-runbook.sh`.

## Workflow

1. Create or update `runbook-params.json` with any parameter overrides the user requested
2. Run `./run-runbook.sh <task-name>`
3. Report the trajectory ID and workflow ID

## Parameters File

If `runbook-params.json` is missing, create it locally at repo root before
launching. The repo `.gitignore` excludes both `runbook-params.json` and
`run-runbook.sh`, so these runbook helper files may exist only in your local
checkout.

Use concrete values in the JSON file instead of shell expressions:

```json
{
  "repository": "ahrav/gossip-rs",
  "pr_number": "312",
  "base_branch": "main",
  "GITHUB_TOKEN": "<output of gh auth token>",
  "CARGO_HOME": "/Users/<you>/.cargo",
  "timeout_sec": 3600
}
```

### Common Overrides

| Parameter | Default | Override for |
|-----------|---------|-------------|
| `timeout_sec` | 3600 (1hr) | Long audits: 7200 (2hr), 10800 (3hr) |
| `pr_number` | varies | PR-specific runbooks (reviews, comment response) |
| `base_branch` | `main` | Auditing a different branch |

Use the Edit tool to update `runbook-params.json` before running the script.
Restore the original value immediately after launching if the override was
one-time — the runbook runs remotely and does not re-read the local file.

## Run the Script

```bash
./run-runbook.sh <task-name>
```

The `<task-name>` matches the filename in `runbooks/` without the `.md` extension.

### List Available Runbooks

```bash
if [ -d runbooks ] && ls runbooks/*.md >/dev/null 2>&1; then
  ls runbooks/*.md | sed 's|runbooks/||;s|\.md$||'
else
  echo "No local runbooks found. Ensure local runbook assets are provisioned."
fi
```

## Output

The script prints trajectory and workflow IDs on success:

```text
Run launched successfully:
  Task:          <task-name>
  Trajectory ID: <id>
  Workflow ID:   <id>
```

Report these to the user so they can track progress in Jetty.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Using RemoteTrigger API directly | Use `run-runbook.sh` — it handles param injection and Jetty API |
| Forgetting to update timeout for long tasks | User-requested timeout goes in `runbook-params.json` `timeout_sec` |
| Passing wrong task name | Name must match a file in `runbooks/` without `.md`. The script lists available names on error. |
| Not reporting trajectory ID | Always show the trajectory and workflow IDs in your response |
| Not knowing which runbook to run | Use the guarded runbook-listing command above and ask the user to pick one |
