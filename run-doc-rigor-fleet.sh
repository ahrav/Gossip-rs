#!/usr/bin/env bash
set -euo pipefail

# Fire-and-forget doc-rigor fleet with state tracking.
#
# Scans all .rs files in crates/, skips files already processed and unchanged,
# takes the next 20 unprocessed files, partitions by crate, launches parallel
# agents, polls, merges branches, creates consolidated PR, cleans up.
#
# Usage:
#   ./run-doc-rigor-fleet.sh              # next 20 unprocessed files
#   ./run-doc-rigor-fleet.sh --full       # ignore state, still capped at 20
#   ./run-doc-rigor-fleet.sh --dry-run    # print plan, don't launch

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
RUNBOOK_FILE="${SCRIPT_DIR}/runbooks/doc-rigor-partitioned.md"
STATE_FILE="${SCRIPT_DIR}/.fleet-state.json"

JETTY_HOST="https://flows-api.jetty.io"
COLLECTION="asdf22223"
AGENT="codex"
MODEL="gpt-5.4"
REPOSITORY="ahrav/gossip-rs"
BASE_BRANCH="main"
TIMEOUT_SEC=5400
DATE=$(date -u +%Y-%m-%d)
POLL_INTERVAL=30
POLL_TIMEOUT=7200
FILE_CAP=40
AGENTS_CAP=10

FULL_MODE=false
DRY_RUN=false

for arg in "$@"; do
  case "$arg" in
    --full) FULL_MODE=true ;;
    --dry-run) DRY_RUN=true ;;
    *) echo "Unknown arg: $arg" >&2; exit 1 ;;
  esac
done

# ── Load .env ───────────────────────────────────────────────────────
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$ENV_FILE" | xargs)
fi

if [[ -z "${JETTY_API_KEY:-}" ]]; then
  echo "ERROR: JETTY_API_KEY not set in .env" >&2
  exit 1
fi

if [[ ! -f "$RUNBOOK_FILE" ]]; then
  echo "ERROR: Runbook not found: ${RUNBOOK_FILE}" >&2
  exit 1
fi

# ── Ensure local repo is on the base branch ────────────────────────
git checkout "${BASE_BRANCH}" --quiet 2>/dev/null || \
  git checkout -f "${BASE_BRANCH}" --quiet 2>/dev/null || true

# ── Push token to Jetty collection env ─────────────────────────────
github_token=$(gh auth token)
echo "Syncing GITHUB_TOKEN to collection env..."
token_payload=$(jq -n --arg token "$github_token" \
  '{"environment_variables": {"GITHUB_TOKEN": $token, "GH_TOKEN": $token}}')
curl -sS -o /dev/null \
  -X PATCH "${JETTY_HOST}/api/v1/collections/${COLLECTION}/environment" \
  -H "Authorization: Bearer ${JETTY_API_KEY}" \
  -H "Content-Type: application/json" \
  --data-binary "$token_payload" \
  --max-time 10

# ── Pin base SHA ───────────────────────────────────────────────────
git fetch origin "${BASE_BRANCH}" --quiet
BASE_SHA=$(git rev-parse "origin/${BASE_BRANCH}")
RUN_SEQ=$(date -u +%H%M)
RUN_ID="doc-rigor-${DATE}-${RUN_SEQ}"
echo "Base SHA: ${BASE_SHA}"

# ── Build candidate list with state filtering ──────────────────────
CANDIDATES=$(python3 - "$STATE_FILE" "$BASE_SHA" "$FULL_MODE" "$FILE_CAP" "$AGENTS_CAP" << 'PYEOF'
import sys, json, os, subprocess

state_file = sys.argv[1]
base_sha = sys.argv[2]
full_mode = sys.argv[3] == "true"
file_cap = int(sys.argv[4])
agents_cap = int(sys.argv[5])

# Load state
state = {}
if not full_mode and os.path.exists(state_file):
    try:
        with open(state_file) as f:
            all_state = json.load(f)
        state = all_state.get("doc-rigor", {})
    except (json.JSONDecodeError, KeyError):
        state = {}

# All .rs files in crates/
raw = subprocess.check_output(
    ["git", "ls-tree", "-r", base_sha, "--name-only", "--", "crates/"],
    text=True
).strip().split("\n")
candidates = sorted(f for f in raw if f.endswith(".rs"))

# Current blob SHAs
blob_output = subprocess.check_output(
    ["git", "ls-tree", "-r", base_sha, "--", "crates/"],
    text=True
).strip().split("\n")

current_blobs = {}
for line in blob_output:
    if not line:
        continue
    parts = line.split()
    if len(parts) >= 4:
        current_blobs[parts[3]] = parts[2]

# Filter by state
to_process = []
skipped = []
for f in candidates:
    blob = current_blobs.get(f, "")
    stored = state.get(f, {})
    if not full_mode and stored.get("blob_sha") == blob and blob:
        skipped.append(f)
    else:
        to_process.append(f)

# Cap
deferred = to_process[file_cap:]
to_process = to_process[:file_cap]

# Distribute files across agents_cap agents (round-robin)
import math
num_agents = min(agents_cap, len(to_process))
buckets = [[] for _ in range(num_agents)]
for i, f in enumerate(to_process):
    buckets[i % num_agents].append(f)

result = {
    "manifests": [],
    "skipped_count": len(skipped),
    "deferred_count": len(deferred),
    "total_candidates": len(candidates),
    "to_process": len(to_process),
}
for i, bucket in enumerate(buckets):
    if not bucket:
        continue
    result["manifests"].append({
        "agent_id": f"batch-{i+1:02d}",
        "files": sorted(bucket),
    })

print(json.dumps(result))
PYEOF
)

TOTAL_CANDIDATES=$(echo "$CANDIDATES" | jq '.total_candidates')
TO_PROCESS=$(echo "$CANDIDATES" | jq '.to_process')
SKIPPED=$(echo "$CANDIDATES" | jq '.skipped_count')
DEFERRED=$(echo "$CANDIDATES" | jq '.deferred_count')
AGENT_COUNT=$(echo "$CANDIDATES" | jq '.manifests | length')

echo ""
echo "Codebase: ${TOTAL_CANDIDATES} .rs files"
echo "Already processed (unchanged): ${SKIPPED}"
echo "Processing this batch: ${TO_PROCESS} (cap: ${FILE_CAP})"
echo "Remaining for future runs: ${DEFERRED}"
echo ""
FILES_PER=$(( TO_PROCESS / AGENT_COUNT ))
echo "Partition: ${AGENT_COUNT} agents (~${FILES_PER} files each)"
echo "================================================"
echo "$CANDIDATES" | jq -r '.manifests[] | "  \(.agent_id): \(.files | length) files"'
echo ""

if [[ "$TO_PROCESS" -eq 0 ]]; then
  echo "Nothing to process. All files are up to date."
  exit 0
fi

if [[ "$DRY_RUN" == "true" ]]; then
  echo "Dry run — not launching agents."
  echo ""
  echo "Files to process:"
  echo "$CANDIDATES" | jq -r '.manifests[].files[]' | sed 's/^/  /'
  exit 0
fi

# ═══════════════════════════════════════════════════════════════════
# Phase 1: Launch agents
# ═══════════════════════════════════════════════════════════════════
runbook=$(<"$RUNBOOK_FILE")
TRAJ_FILE="${SCRIPT_DIR}/doc-rigor-trajectories-${RUN_ID}.txt"
rm -f "$TRAJ_FILE"

echo "Launching ${AGENT_COUNT} agents..."
echo ""

echo "$CANDIDATES" | jq -c '.manifests[]' | while IFS= read -r manifest; do
  agent_id=$(echo "$manifest" | jq -r '.agent_id')
  file_manifest=$(echo "$manifest" | jq '.files')

  agent_runbook="$runbook"
  agent_runbook="${agent_runbook//\{\{repository\}\}/$REPOSITORY}"
  agent_runbook="${agent_runbook//\{\{base_branch\}\}/$BASE_BRANCH}"
  agent_runbook="${agent_runbook//\{\{base_sha\}\}/$BASE_SHA}"
  agent_runbook="${agent_runbook//\{\{agent_id\}\}/$agent_id}"
  agent_runbook="${agent_runbook//\{\{run_id\}\}/$RUN_ID}"
  escaped_manifest=$(echo "$file_manifest" | sed 's/[&/\]/\\&/g')
  agent_runbook="${agent_runbook//\{\{file_manifest\}\}/$escaped_manifest}"

  user_message="Run doc-rigor for crate '${agent_id}' on ${REPOSITORY} at ${BASE_SHA:0:8}. Improve documentation for $(echo "$file_manifest" | jq 'length') files."

  payload=$(jq -n \
    --arg agent "$AGENT" \
    --arg model "$MODEL" \
    --arg runbook "$agent_runbook" \
    --arg user_msg "$user_message" \
    --arg collection "$COLLECTION" \
    --argjson timeout "$TIMEOUT_SEC" \
    '{
      agent: $agent,
      model: $model,
      reasoning_effort: "high",
      timeout: $timeout,
      timeout_sec: $timeout,
      messages: [
        { role: "system", content: $runbook },
        { role: "user", content: $user_msg }
      ],
      stream: false,
      jetty: {
        runbook: true,
        collection: $collection,
        task: "doc-rigor",
        timeout_sec: $timeout,
        timeout: $timeout,
        timeout_hint: 10
      }
    }')

  response=$(curl -sS -w "\n%{http_code}" \
    -X POST "${JETTY_HOST}/v1/chat/completions" \
    -H "Authorization: Bearer ${JETTY_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    --max-time 60)

  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')

  trajectory_id=$(echo "$body" | jq -r '.jetty_metadata.trajectory_id // empty')
  workflow_id=$(echo "$body" | jq -r '.jetty_metadata.workflow_id // .id // empty')

  if [[ -z "$trajectory_id" && -n "$workflow_id" ]]; then
    trajectory_id="${workflow_id##*--}"
  fi

  if [[ -z "$trajectory_id" && "$http_code" -ge 400 ]]; then
    err=$(echo "$body" | jq -r '.error.message // .error // .detail // empty')
    echo "  FAIL: ${agent_id} (HTTP ${http_code}): ${err:-$body}"
    continue
  fi

  echo "  ${agent_id}: trajectory=${trajectory_id}"
  echo "${agent_id} ${trajectory_id} ${workflow_id}" >> "$TRAJ_FILE"
done

if [[ ! -f "$TRAJ_FILE" ]]; then
  echo "ERROR: No agents launched successfully." >&2
  exit 1
fi

echo ""
echo "All agents launched. Polling for completion..."
echo ""

# ═══════════════════════════════════════════════════════════════════
# Phase 2: Poll until all agents complete
# ═══════════════════════════════════════════════════════════════════
TOTAL=$(wc -l < "$TRAJ_FILE" | tr -d ' ')
ELAPSED=0

while [[ $ELAPSED -lt $POLL_TIMEOUT ]]; do
  COMPLETED=0; RUNNING=0; FAILED=0
  while IFS=' ' read -r aid tid wid; do
    st=$(curl -s -H "Authorization: Bearer ${JETTY_API_KEY}" \
      "${JETTY_HOST}/api/v1/db/trajectory/${COLLECTION}/doc-rigor/${tid}" \
      | jq -r '.status // "unknown"')
    case "$st" in
      completed) ((COMPLETED++)) ;;
      failed|cancelled) ((FAILED++)) ;;
      *) ((RUNNING++)) ;;
    esac
  done < "$TRAJ_FILE"

  echo "  [${ELAPSED}s] completed=${COMPLETED} running=${RUNNING} failed=${FAILED} / ${TOTAL}"

  if [[ $((COMPLETED + FAILED)) -eq $TOTAL ]]; then
    echo ""
    echo "All agents finished. (completed=${COMPLETED} failed=${FAILED})"
    break
  fi

  sleep $POLL_INTERVAL
  ((ELAPSED += POLL_INTERVAL))
done

if [[ $ELAPSED -ge $POLL_TIMEOUT ]]; then
  echo "WARNING: Timed out after ${POLL_TIMEOUT}s."
fi

# ═══════════════════════════════════════════════════════════════════
# Phase 3: Merge agent branches into consolidated PR
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "Merging agent branches..."

# Use a temporary clone for merge/push to avoid conflicts with the
# user's working tree (dirty state, pre-push hooks checking beads, etc.)
TMPDIR=$(mktemp -d)
MERGE_REPO="${TMPDIR}/gossip-rs"
git clone --quiet --no-checkout "$(git remote get-url origin)" "$MERGE_REPO"
cd "$MERGE_REPO"
git checkout -b "${RUN_ID}-merge" "origin/${BASE_BRANCH}" --quiet

# Configure git identity for merge commits
git config user.name "fleet-orchestrator"
git config user.email "fleet@gossip-rs.local"

UMBRELLA_BRANCH="doc-rigor/consolidated/${RUN_ID}"

MERGED=0
MERGE_FAILURES=""

while IFS=' ' read -r aid tid wid; do
  branch="doc-rigor/${aid}/${RUN_ID}"

  if ! git ls-remote --exit-code origin "refs/heads/${branch}" &>/dev/null; then
    echo "  ${aid}: no branch pushed"
    continue
  fi

  git fetch origin "${branch}" --quiet

  if git merge "origin/${branch}" --no-edit -m "Merge ${aid} doc-rigor fixes" 2>/dev/null; then
    echo "  ${aid}: merged"
    ((MERGED++))
  else
    echo "  ${aid}: MERGE CONFLICT"
    git merge --abort
    MERGE_FAILURES="${MERGE_FAILURES} ${aid}"
  fi
done < "$TRAJ_FILE"

echo ""
echo "Merged ${MERGED} branches."

if [[ $MERGED -eq 0 ]]; then
  echo "No branches to merge."
  cd "$SCRIPT_DIR"
  rm -rf "$TMPDIR"
  exit 0
fi

# ── Post-merge verification (non-fatal) ────────────────────────────
# Run compiler checks on the consolidated branch. Failures are reported
# in the PR body but do NOT block PR creation — the PR itself is the
# artifact for review and fixing.
echo ""
echo "Running post-merge verification..."
VERIFY_NOTES=""
cargo fmt --all -- --check 2>/dev/null && echo "  PASS: cargo fmt" || { echo "  WARN: cargo fmt failed"; VERIFY_NOTES="${VERIFY_NOTES}\n- cargo fmt: FAILED"; }
cargo check --all-features 2>/dev/null && echo "  PASS: cargo check" || { echo "  WARN: cargo check failed"; VERIFY_NOTES="${VERIFY_NOTES}\n- cargo check: FAILED"; }
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features 2>/dev/null && echo "  PASS: cargo doc" || { echo "  WARN: cargo doc failed"; VERIFY_NOTES="${VERIFY_NOTES}\n- cargo doc: FAILED"; }
if [[ -z "$VERIFY_NOTES" ]]; then
  VERIFY_NOTES="All checks passed."
fi

# ── Push and create PR ─────────────────────────────────────────────
git push origin "HEAD:refs/heads/${UMBRELLA_BRANCH}"

TRAJ_LINKS=""
while IFS=' ' read -r aid tid wid; do
  TRAJ_LINKS="${TRAJ_LINKS}
- **${aid}**: [${tid}](https://flows.jetty.io/${COLLECTION}/doc-rigor/${tid})"
done < "$TRAJ_FILE"

gh pr create \
  --repo "${REPOSITORY}" \
  --base "${BASE_BRANCH}" \
  --head "${UMBRELLA_BRANCH}" \
  --title "docs: doc-rigor sweep (${DATE})" \
  --body "$(cat <<EOF
## Doc Rigor Sweep

Next ${TO_PROCESS} unprocessed files (${DEFERRED} remaining after this batch).

### Summary

| Metric | Count |
|--------|-------|
| Files processed | ${TO_PROCESS} |
| Agents launched | ${TOTAL} |
| Branches merged | ${MERGED} |
| Already processed (skipped) | ${SKIPPED} |
| Remaining for future runs | ${DEFERRED} |

### Verification

$(echo -e "${VERIFY_NOTES}")

### Agent Trajectories
${TRAJ_LINKS}
EOF
)"

echo ""
echo "PR created: $(gh pr view --repo "${REPOSITORY}" "${UMBRELLA_BRANCH}" --json url --jq '.url')"

# ── Clean up agent branches ───────────────────────────────────────
echo ""
echo "Cleaning up agent branches..."
while IFS=' ' read -r aid tid wid; do
  branch="doc-rigor/${aid}/${RUN_ID}"
  gh api -X DELETE "repos/${REPOSITORY}/git/refs/heads/${branch}" 2>/dev/null && echo "  deleted: ${branch}" || true
done < "$TRAJ_FILE"

# Done with temp clone
cd "$SCRIPT_DIR"
rm -rf "$TMPDIR"

# ═══════════════════════════════════════════════════════════════════
# Phase 4: Update state ledger
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "Updating state ledger..."

python3 - "$STATE_FILE" "$BASE_SHA" "$RUN_ID" "$CANDIDATES" << 'PYEOF'
import sys, json, os, subprocess
from datetime import datetime, timezone

state_file = sys.argv[1]
base_sha = sys.argv[2]
run_id = sys.argv[3]
candidates = json.loads(sys.argv[4])

all_state = {}
if os.path.exists(state_file):
    try:
        with open(state_file) as f:
            all_state = json.load(f)
    except (json.JSONDecodeError, KeyError):
        pass

doc_rigor_state = all_state.get("doc-rigor", {})

blob_output = subprocess.check_output(
    ["git", "ls-tree", "-r", base_sha, "--", "crates/"],
    text=True
).strip().split("\n")

current_blobs = {}
for line in blob_output:
    parts = line.split()
    if len(parts) >= 4:
        current_blobs[parts[3]] = parts[2]

now = datetime.now(timezone.utc).isoformat()
for manifest in candidates["manifests"]:
    for f in manifest["files"]:
        doc_rigor_state[f] = {
            "blob_sha": current_blobs.get(f, ""),
            "processed_at": now,
            "run_id": run_id,
        }

all_state["doc-rigor"] = doc_rigor_state

with open(state_file, "w") as f:
    json.dump(all_state, f, indent=2, sort_keys=True)

print(f"  Updated {len(candidates['manifests'])} crates, "
      f"{sum(len(m['files']) for m in candidates['manifests'])} files")
PYEOF

# ── Ensure local repo is back on the base branch ──────────────────
cd "$SCRIPT_DIR"
git checkout "${BASE_BRANCH}" --quiet 2>/dev/null || \
  git checkout -f "${BASE_BRANCH}" --quiet 2>/dev/null || true

echo ""
echo "Done. PR is ready for review."
