#!/usr/bin/env bash
# Reads review-findings.jsonl and groups findings by (category, subcategory).
# Produces a JSON report classifying each group as a codification candidate,
# below-threshold (monitoring), or noisy (FP rate > 15%).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FINDINGS_FILE="$CLAUDE_DIR/review-findings.jsonl"

# ── Dependency check ──────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
  echo >&2 "Error: jq is required but not installed."
  echo >&2 "  macOS: brew install jq"
  echo >&2 "  Linux: apt-get install jq / yum install jq"
  exit 1
fi

# ── Empty / missing file produces an empty report ────────────────────────────
if [[ ! -f "$FINDINGS_FILE" ]] || [[ ! -s "$FINDINGS_FILE" ]]; then
  jq -n '{
    analysis_date: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
    total_findings: 0,
    patterns_detected: [],
    below_threshold: [],
    noisy_patterns: []
  }'
  exit 0
fi

# ── Parse JSONL, skipping malformed lines ─────────────────────────────────────
# Build a valid JSON array from the JSONL, discarding lines that fail to parse.
VALID_JSON=$(
  line_num=0
  echo "["
  first=true
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_num=$((line_num + 1))
    # Skip empty lines
    [[ -z "${line// /}" ]] && continue
    # Validate JSON
    if ! echo "$line" | jq -e '.' &>/dev/null; then
      echo >&2 "Warning: skipping malformed JSON at line $line_num"
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
)

TOTAL_FINDINGS=$(echo "$VALID_JSON" | jq 'length')

if [[ "$TOTAL_FINDINGS" -eq 0 ]]; then
  jq -n '{
    analysis_date: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
    total_findings: 0,
    patterns_detected: [],
    below_threshold: [],
    noisy_patterns: []
  }'
  exit 0
fi

# ── Group by (category, subcategory), compute counts and FP rates ─────────────
# Classification thresholds:
#   count >= 3 and fp_rate <= 0.15 -> "codify" candidate
#   count >= 3 and fp_rate >  0.15 -> "noisy" (suppress)
#   count <  3                     -> "below_threshold" (monitoring)
echo "$VALID_JSON" | jq '
  def analysis_date: now | strftime("%Y-%m-%dT%H:%M:%SZ");

  group_by(.category + "|" + (.subcategory // "uncategorized"))
  | map({
      category: .[0].category,
      subcategory: (.[0].subcategory // "uncategorized"),
      total_count: length,
      true_positive_count: [.[] | select(.resolution.was_true_positive == true)] | length,
      false_positive_count: [.[] | select(.resolution.was_true_positive == false)] | length,
      unresolved_count: [.[] | select(.resolution.was_true_positive == null or .resolution == null)] | length,
      severities: [.[].severity] | group_by(.) | map({(.[0]): length}) | add,
      representative_findings: [.[] | {id, title, file, line, severity, description}][:3],
      files_affected: [.[].file] | unique
    })
  | map(
      # FP rate denominator uses only resolved findings (TP + FP)
      . + {
        resolved_count: (.true_positive_count + .false_positive_count),
        fp_rate: (
          if (.true_positive_count + .false_positive_count) == 0 then 0
          else (.false_positive_count / (.true_positive_count + .false_positive_count))
          end
        )
      }
    )
  | {
      analysis_date: analysis_date,
      total_findings: (map(.total_count) | add),
      patterns_detected: [
        .[] | select(.total_count >= 3 and .fp_rate <= 0.15)
        | . + {recommendation: "codify"}
      ] | sort_by(-.total_count),
      below_threshold: [
        .[] | select(.total_count < 3)
        | . + {recommendation: "monitor"}
      ] | sort_by(-.total_count),
      noisy_patterns: [
        .[] | select(.total_count >= 3 and .fp_rate > 0.15)
        | . + {recommendation: "suppress"}
      ] | sort_by(-.total_count)
    }
'
