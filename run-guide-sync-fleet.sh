#!/usr/bin/env bash
# Wrapper script for the fleet-orchestrator guide-sync pipeline.
#
# Loads environment from .env, syncs the current GitHub token to the Jetty
# collection, then runs the orchestrator binary with all forwarded arguments.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

# Load .env if present (same pattern as run-doc-rigor-fleet.sh).
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$ENV_FILE" | xargs)
fi

if [[ -z "${JETTY_API_KEY:-}" ]]; then
  echo "ERROR: JETTY_API_KEY not set (check .env or export it)" >&2
  exit 1
fi

# Sync the current GitHub token into the Jetty collection environment so
# that launched agents can authenticate against GitHub.
github_token="$(gh auth token)"
echo "Syncing GITHUB_TOKEN to Jetty collection environment..."
token_payload=$(jq -n --arg token "$github_token" \
  '{"environment_variables": {"GITHUB_TOKEN": $token, "GH_TOKEN": $token}}')
curl -sS -o /dev/null \
  -X PATCH "https://flows-api.jetty.io/api/v1/collections/asdf22223/environment" \
  -H "Authorization: Bearer ${JETTY_API_KEY}" \
  -H "Content-Type: application/json" \
  --data-binary "$token_payload" \
  --max-time 10

echo "Running fleet-orchestrator..."
cargo run -p fleet-orchestrator -- "$@"
