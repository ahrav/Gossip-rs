#!/usr/bin/env bash
# Reads review-rules.yaml and review-findings.jsonl to produce a lifecycle
# report: stale rules, noisy rules (FP > 15%), and promotion candidates.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RULES_FILE="$CLAUDE_DIR/review-rules.yaml"
FINDINGS_FILE="$CLAUDE_DIR/review-findings.jsonl"

# ── Dependency checks ─────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  echo >&2 "Error: jq is required but not installed."
  echo >&2 "  macOS: brew install jq"
  echo >&2 "  Linux: apt-get install jq / yum install jq"
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo >&2 "Error: python3 is required but not installed."
  exit 1
fi

# Verify PyYAML is importable
if ! python3 -c "import yaml" &>/dev/null 2>&1; then
  echo >&2 "Error: PyYAML is required but not installed."
  echo >&2 "  pip3 install pyyaml"
  exit 1
fi

# ── Empty / missing rules file produces an empty report ──────────────────────
if [[ ! -f "$RULES_FILE" ]] || [[ ! -s "$RULES_FILE" ]]; then
  jq -n '{
    report_date: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
    stale_rules: [],
    noisy_rules: [],
    promotion_candidates: [],
    active_count: 0,
    advisory_count: 0,
    disabled_count: 0,
    overall_fp_rate: 0
  }'
  exit 0
fi

# ── Convert YAML rules to JSON via python3 ───────────────────────────────────
RULES_JSON=$(python3 << PYEOF
import sys, json, yaml

with open("$RULES_FILE", "r") as f:
    data = yaml.safe_load(f)

if data is None or "rules" not in data or data["rules"] is None:
    print(json.dumps({"rules": []}))
else:
    print(json.dumps(data, default=str))
PYEOF
)

RULE_COUNT=$(echo "$RULES_JSON" | jq '.rules | length')

if [[ "$RULE_COUNT" -eq 0 ]]; then
  jq -n '{
    report_date: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
    stale_rules: [],
    noisy_rules: [],
    promotion_candidates: [],
    active_count: 0,
    advisory_count: 0,
    disabled_count: 0,
    overall_fp_rate: 0
  }'
  exit 0
fi

# ── Build findings FP stats by (category|subcategory) from JSONL ─────────────
FINDINGS_STATS="{}"
if [[ -f "$FINDINGS_FILE" ]] && [[ -s "$FINDINGS_FILE" ]]; then
  FINDINGS_STATS=$(
    # Parse JSONL into a JSON array, skipping malformed lines
    (
      echo "["
      first=true
      while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "${line// /}" ]] && continue
        if ! echo "$line" | jq -e '.' &>/dev/null; then
          echo >&2 "Warning: skipping malformed JSON line in findings"
          continue
        fi
        if [[ "$first" == "true" ]]; then
          first=false
        else
          echo ","
        fi
        echo "$line"
      done < "$FINDINGS_FILE"
      echo "]"
    ) | jq '
      # Group by category+subcategory and compute per-group FP stats
      group_by((.category // "") + "|" + (.subcategory // ""))
      | map({
          key: (.[0].category + "|" + (.[0].subcategory // "")),
          value: {
            total: length,
            tp: [.[] | select(.resolution.was_true_positive == true)] | length,
            fp: [.[] | select(.resolution.was_true_positive == false)] | length
          }
        })
      | from_entries
    '
  )
fi

# ── Compute lifecycle report ─────────────────────────────────────────────────
NOW_EPOCH=$(date +%s)
THIRTY_DAYS_AGO_EPOCH=$((NOW_EPOCH - 30 * 86400))
SEVEN_DAYS_AGO_EPOCH=$((NOW_EPOCH - 7 * 86400))

# Single jq invocation for the full report
jq -n \
  --argjson rules "$RULES_JSON" \
  --argjson findings_stats "$FINDINGS_STATS" \
  --argjson thirty_days_ago "$THIRTY_DAYS_AGO_EPOCH" \
  --argjson seven_days_ago "$SEVEN_DAYS_AGO_EPOCH" \
'
  def to_epoch:
    # Parse ISO 8601 date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ) to epoch.
    # Returns null for null/empty input.
    if . == null or . == "" then null
    elif test("T") then (split("T")[0] | strptime("%Y-%m-%d") | mktime)
    else (strptime("%Y-%m-%d") | mktime)
    end;

  def fp_rate_for_rule:
    # Look up FP stats from the findings for a rule key.
    # Falls back to the rule own lifecycle counters when no findings match.
    .key as $key |
    if $findings_stats[$key] != null then
      $findings_stats[$key] |
      if (.tp + .fp) == 0 then 0
      else (.fp / (.tp + .fp))
      end
    else
      if (.match_count + .false_positive_count) == 0 then 0
      else (.false_positive_count / (.match_count + .false_positive_count))
      end
    end;

  ($rules.rules // []) as $all_rules |

  # Status counts
  ($all_rules | map(select(.status == "active")) | length) as $active_count |
  ($all_rules | map(select(.status == "advisory")) | length) as $advisory_count |
  ($all_rules | map(select(.status == "disabled")) | length) as $disabled_count |

  # Stale rules: active rules where last_matched is null or > 30 days ago
  [
    $all_rules[] |
    select(.status == "active") |
    {
      id,
      status,
      category,
      subcategory,
      last_matched: .lifecycle.last_matched,
      last_matched_epoch: (.lifecycle.last_matched | to_epoch),
      match_count: (.lifecycle.match_count // 0),
      created_date: .lifecycle.created_date
    } |
    select(
      .last_matched == null or
      .last_matched == "" or
      (.last_matched_epoch != null and .last_matched_epoch < $thirty_days_ago)
    ) |
    del(.last_matched_epoch)
  ] as $stale_rules |

  # Noisy rules: active or advisory rules with FP rate > 15%
  [
    $all_rules[] |
    select(.status == "active" or .status == "advisory") |
    {
      id,
      status,
      category,
      subcategory,
      key: (.category + "|" + (.subcategory // "")),
      match_count: (.lifecycle.match_count // 0),
      false_positive_count: (.lifecycle.false_positive_count // 0)
    } |
    . + { fp_rate: (. | fp_rate_for_rule) } |
    select(.fp_rate > 0.15) |
    del(.key)
  ] as $noisy_rules |

  # Promotion candidates: advisory rules > 7 days old with FP < 15%
  [
    $all_rules[] |
    select(.status == "advisory") |
    {
      id,
      status,
      category,
      subcategory,
      key: (.category + "|" + (.subcategory // "")),
      created_date: .lifecycle.created_date,
      created_epoch: (.lifecycle.created_date | to_epoch),
      match_count: (.lifecycle.match_count // 0),
      false_positive_count: (.lifecycle.false_positive_count // 0)
    } |
    . + { fp_rate: (. | fp_rate_for_rule) } |
    select(
      .created_epoch != null and
      .created_epoch < $seven_days_ago and
      .fp_rate <= 0.15
    ) |
    del(.key, .created_epoch)
  ] as $promotion_candidates |

  # Overall FP rate across all resolved findings
  (
    [$findings_stats | to_entries[] | .value.fp] | add // 0
  ) as $total_fp |
  (
    [$findings_stats | to_entries[] | .value | (.tp + .fp)] | add // 0
  ) as $total_resolved |
  (
    if $total_resolved == 0 then 0
    else ($total_fp / $total_resolved)
    end
  ) as $overall_fp_rate |

  {
    report_date: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
    stale_rules: $stale_rules,
    noisy_rules: $noisy_rules,
    promotion_candidates: $promotion_candidates,
    active_count: $active_count,
    advisory_count: $advisory_count,
    disabled_count: $disabled_count,
    overall_fp_rate: ($overall_fp_rate * 100 | round / 100)
  }
'
