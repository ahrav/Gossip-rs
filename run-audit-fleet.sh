#!/usr/bin/env bash
set -euo pipefail

# Fire-and-forget design doc audit fleet.
#
# One agent per doc/diagram file. Tracks processed files via blob SHA ledger
# to skip unchanged files. Caps at 20 files per run for reviewable PRs.
# Launches agents, polls, merges branches, creates PR, cleans up.
#
# Usage:
#   ./run-audit-fleet.sh              # next 20 unprocessed doc/diagram files
#   ./run-audit-fleet.sh --full       # ignore state, still capped at 20
#   ./run-audit-fleet.sh --dry-run    # print plan, don't launch

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
RUNBOOK_FILE="${SCRIPT_DIR}/runbooks/design-doc-audit-partitioned.md"
SCOPE_MAP="${SCRIPT_DIR}/docs/scope-map.toml"
STATE_FILE="${SCRIPT_DIR}/.fleet-state.json"

JETTY_HOST="https://flows-api.jetty.io"
COLLECTION="asdf22223"
AGENT="gemini-cli"
MODEL="gemini/gemini-3.1-pro-preview"
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

for f in "$RUNBOOK_FILE" "$SCOPE_MAP"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: Required file not found: ${f}" >&2
    exit 1
  fi
done

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
RUN_ID="audit-${DATE}-${RUN_SEQ}"
echo "Base SHA: ${BASE_SHA}"

# ── Build candidate list with state filtering ──────────────────────
CANDIDATES=$(python3 - "$SCOPE_MAP" "$STATE_FILE" "$BASE_SHA" "$FULL_MODE" "$FILE_CAP" "$AGENTS_CAP" << 'PYEOF'
import sys, json, os, subprocess, re
from collections import defaultdict

scope_map_path = sys.argv[1]
state_file = sys.argv[2]
base_sha = sys.argv[3]
full_mode = sys.argv[4] == "true"
file_cap = int(sys.argv[5])
agents_cap = int(sys.argv[6])

# ── Load state ────────────────────────────────────────────────────
state = {}
if not full_mode and os.path.exists(state_file):
    try:
        with open(state_file) as f:
            all_state = json.load(f)
        state = all_state.get("design-doc-audit", {})
    except (json.JSONDecodeError, KeyError):
        state = {}

# ── Parse scope-map.toml ──────────────────────────────────────────
scopes = []
with open(scope_map_path) as f:
    content = f.read()
blocks = re.split(r'\[\[scopes\]\]', content)[1:]
for block in blocks:
    doc_m = re.search(r'doc\s*=\s*"([^"]+)"', block)
    dir_m = re.search(r'dir\s*=\s*"([^"]+)"', block)
    if doc_m and dir_m:
        scopes.append({"doc": doc_m.group(1), "dir": dir_m.group(1)})

doc_dirs = defaultdict(set)
for s in scopes:
    doc_dirs[s["doc"]].add(s["dir"])

# ── Enumerate all doc and diagram files ───────────────────────────
all_files = []
for root, dirs, files in os.walk("docs"):
    if "findings" in root:
        continue
    for f in sorted(files):
        if f.endswith(".md"):
            all_files.append(("doc", os.path.join(root, f)))

for root, dirs, files in os.walk("diagrams"):
    for f in sorted(files):
        if f.endswith(".md"):
            all_files.append(("diagram", os.path.join(root, f)))

# ── Get current blob SHAs for docs/ and diagrams/ ────────────────
current_blobs = {}
for prefix in ["docs/", "diagrams/"]:
    try:
        blob_output = subprocess.check_output(
            ["git", "ls-tree", "-r", base_sha, "--", prefix],
            text=True
        ).strip().split("\n")
        for line in blob_output:
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                current_blobs[parts[3]] = parts[2]
    except subprocess.CalledProcessError:
        pass

# ── Filter by state ──────────────────────────────────────────────
to_process = []
skipped = []
for ftype, fpath in all_files:
    blob = current_blobs.get(fpath, "")
    stored = state.get(fpath, {})
    if not full_mode and stored.get("blob_sha") == blob and blob:
        skipped.append(fpath)
    else:
        to_process.append((ftype, fpath))

# ── Cap ──────────────────────────────────────────────────────────
deferred = to_process[file_cap:]
to_process = to_process[:file_cap]

# ── Distribute files across agents_cap agents (round-robin) ──────
import math
num_agents = min(agents_cap, len(to_process))
buckets = [[] for _ in range(num_agents)]
for i, item in enumerate(to_process):
    buckets[i % num_agents].append(item)

manifests = []
for i, bucket in enumerate(buckets):
    if not bucket:
        continue
    doc_files = [fpath for ftype, fpath in bucket if ftype == "doc"]
    diagram_files = [fpath for ftype, fpath in bucket if ftype == "diagram"]
    source_dirs = set()
    for ftype, fpath in bucket:
        source_dirs.update(doc_dirs.get(fpath, set()))
    manifests.append({
        "agent_id": f"batch-{i+1:02d}",
        "doc_files": sorted(doc_files),
        "diagram_files": sorted(diagram_files),
        "source_dirs": sorted(source_dirs),
        "base_sha": base_sha,
    })

result = {
    "manifests": manifests,
    "skipped_count": len(skipped),
    "deferred_count": len(deferred),
    "total_candidates": len(all_files),
    "to_process": len(to_process),
}
print(json.dumps(result))
PYEOF
)

TOTAL_CANDIDATES=$(echo "$CANDIDATES" | jq '.total_candidates')
TO_PROCESS=$(echo "$CANDIDATES" | jq '.to_process')
SKIPPED=$(echo "$CANDIDATES" | jq '.skipped_count')
DEFERRED=$(echo "$CANDIDATES" | jq '.deferred_count')
AGENT_COUNT=$(echo "$CANDIDATES" | jq '.manifests | length')

echo ""
echo "Docs + diagrams: ${TOTAL_CANDIDATES} files"
echo "Already processed (unchanged): ${SKIPPED}"
echo "Processing this batch: ${TO_PROCESS} (cap: ${FILE_CAP})"
echo "Remaining for future runs: ${DEFERRED}"
echo ""
echo "Partition: ${AGENT_COUNT} agents (~$(( TO_PROCESS / AGENT_COUNT )) files each)"
echo "================================================"
echo "$CANDIDATES" | jq -r '.manifests[] | "  \(.agent_id): \(.doc_files | length) docs, \(.diagram_files | length) diagrams"'
echo ""

if [[ "$TO_PROCESS" -eq 0 ]]; then
  echo "Nothing to process. All files are up to date."
  exit 0
fi

if [[ "$DRY_RUN" == "true" ]]; then
  echo "Dry run — not launching agents."
  exit 0
fi

# ═══════════════════════════════════════════════════════════════════
# Phase 1: Launch agents
# ═══════════════════════════════════════════════════════════════════
runbook=$(<"$RUNBOOK_FILE")
TRAJ_FILE="${SCRIPT_DIR}/audit-trajectories-${RUN_ID}.txt"
rm -f "$TRAJ_FILE"

echo "Launching ${AGENT_COUNT} agents..."
echo ""

echo "$CANDIDATES" | jq -c '.manifests[]' | while IFS= read -r manifest; do
  agent_id=$(echo "$manifest" | jq -r '.agent_id')

  agent_runbook="$runbook"
  agent_runbook="${agent_runbook//\{\{repository\}\}/$REPOSITORY}"
  agent_runbook="${agent_runbook//\{\{base_branch\}\}/$BASE_BRANCH}"
  agent_runbook="${agent_runbook//\{\{base_sha\}\}/$BASE_SHA}"
  agent_runbook="${agent_runbook//\{\{agent_id\}\}/$agent_id}"
  agent_runbook="${agent_runbook//\{\{run_id\}\}/$RUN_ID}"
  escaped_manifest=$(echo "$manifest" | sed 's/[&/\]/\\&/g')
  agent_runbook="${agent_runbook//\{\{audit_manifest\}\}/$escaped_manifest}"

  user_message="Run design-doc-audit for '${agent_id}' on ${REPOSITORY} at ${BASE_SHA:0:8}."

  payload=$(jq -n \
    --arg agent "$AGENT" \
    --arg model "$MODEL" \
    --arg runbook "$agent_runbook" \
    --arg user_msg "$user_message" \
    --arg collection "$COLLECTION" \
    --arg task "design-doc-audit" \
    --argjson timeout "$TIMEOUT_SEC" \
    '{
      agent: $agent,
      model: $model,
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
        task: "design-doc-audit",
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
      "${JETTY_HOST}/api/v1/db/trajectory/${COLLECTION}/design-doc-audit/${tid}" \
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

git config user.name "fleet-orchestrator"
git config user.email "fleet@gossip-rs.local"

UMBRELLA_BRANCH="audit/consolidated/${DATE}"

MERGED=0
MERGE_FAILURES=""

while IFS=' ' read -r aid tid wid; do
  branch="audit/${aid}/${RUN_ID}"

  if ! git ls-remote --exit-code origin "refs/heads/${branch}" &>/dev/null; then
    echo "  ${aid}: no branch pushed"
    continue
  fi

  git fetch origin "${branch}" --quiet

  if git merge "origin/${branch}" --no-edit -m "Merge ${aid} audit fixes" 2>/dev/null; then
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
  # Still update state — files were audited even if no drift found
  echo "Updating state ledger (no drift found)..."
  python3 - "$STATE_FILE" "$BASE_SHA" "$RUN_ID" "$CANDIDATES" << 'PYEOF_NODRIFT'
import sys, json, os, subprocess
from datetime import datetime, timezone
state_file, base_sha, run_id = sys.argv[1], sys.argv[2], sys.argv[3]
candidates = json.loads(sys.argv[4])
all_state = {}
if os.path.exists(state_file):
    try:
        with open(state_file) as f: all_state = json.load(f)
    except: pass
st = all_state.get('design-doc-audit', {})
blobs = {}
for prefix in ['docs/', 'diagrams/']:
    try:
        for line in subprocess.check_output(['git','ls-tree','-r',base_sha,'--',prefix],text=True).strip().split('\n'):
            if not line: continue
            p = line.split()
            if len(p)>=4: blobs[p[3]]=p[2]
    except: pass
now = datetime.now(timezone.utc).isoformat()
for m in candidates['manifests']:
    for f in m['doc_files'] + m['diagram_files']:
        st[f] = {'blob_sha': blobs.get(f,''), 'processed_at': now, 'run_id': run_id}
all_state['design-doc-audit'] = st
with open(state_file,'w') as f: json.dump(all_state,f,indent=2,sort_keys=True)
print(f"  Updated {len(candidates['manifests'])} files")
PYEOF_NODRIFT
  exit 0
fi

# ── Post-merge verification (non-fatal) ────────────────────────────
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
- **${aid}**: [${tid}](https://flows.jetty.io/${COLLECTION}/design-doc-audit/${tid})"
done < "$TRAJ_FILE"

gh pr create \
  --repo "${REPOSITORY}" \
  --base "${BASE_BRANCH}" \
  --head "${UMBRELLA_BRANCH}" \
  --title "docs: design doc audit sweep (${DATE})" \
  --body "$(cat <<EOF
## Design Doc Audit Sweep

Next ${TO_PROCESS} unprocessed docs/diagrams (${DEFERRED} remaining after this batch).

### Summary

| Metric | Count |
|--------|-------|
| Files audited | ${TO_PROCESS} |
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
  branch="audit/${aid}/${RUN_ID}"
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

audit_state = all_state.get("design-doc-audit", {})

current_blobs = {}
for prefix in ["docs/", "diagrams/"]:
    try:
        for line in subprocess.check_output(
            ["git", "ls-tree", "-r", base_sha, "--", prefix], text=True
        ).strip().split("\n"):
            if not line: continue
            parts = line.split()
            if len(parts) >= 4:
                current_blobs[parts[3]] = parts[2]
    except subprocess.CalledProcessError:
        pass

now = datetime.now(timezone.utc).isoformat()
for manifest in candidates["manifests"]:
    for f in manifest["doc_files"] + manifest["diagram_files"]:
        audit_state[f] = {
            "blob_sha": current_blobs.get(f, ""),
            "processed_at": now,
            "run_id": run_id,
        }

all_state["design-doc-audit"] = audit_state

with open(state_file, "w") as f:
    json.dump(all_state, f, indent=2, sort_keys=True)

print(f"  Updated {len(candidates['manifests'])} files")
PYEOF

# ── Ensure local repo is back on the base branch ──────────────────
cd "$SCRIPT_DIR"
git checkout "${BASE_BRANCH}" --quiet 2>/dev/null || \
  git checkout -f "${BASE_BRANCH}" --quiet 2>/dev/null || true

echo ""
echo "Done. PR is ready for review."
