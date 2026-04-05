#!/usr/bin/env bash
#
# review-pattern-check.sh — Checks modified files against codified review rules.
#
# Reads active and advisory rules from .claude/review-rules.yaml and scans
# modified files for known review patterns. Only reports matches; produces
# zero output when nothing matches (silent by default).
#
# Runs as a Stop hook (once per agent turn, not per edit).
#
# Flags:
#   --ci-mode  Only check "active" rules. Exit 1 on any match.
#
# Exit codes:
#   0 - No active-rule matches (or no rules file, or no modified files)
#   1 - (--ci-mode only) Active rule matched

set -euo pipefail

# --- Parse flags ---
CI_MODE=0
for arg in "$@"; do
    [[ "$arg" == "--ci-mode" ]] && CI_MODE=1
done

# --- Locate repo root ---
REPO_ROOT=""
if command -v git &>/dev/null; then
    REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
fi
[[ -z "$REPO_ROOT" ]] && exit 0

RULES_FILE="$REPO_ROOT/.claude/review-rules.yaml"
[[ ! -f "$RULES_FILE" ]] && exit 0

# --- Get modified files (staged + unstaged, relative to repo root) ---
cd "$REPO_ROOT"
MODIFIED_FILES=$(git diff --name-only HEAD 2>/dev/null || git diff --name-only 2>/dev/null || true)
[[ -z "$MODIFIED_FILES" ]] && exit 0

# --- Parse rules from YAML ---
# Each rule block starts with "  - id:" and contains fields indented under it.
# Uses a line-by-line state machine since yq may not be available.

declare -a RULE_IDS=()
declare -a RULE_STATUSES=()
declare -a RULE_WHATS=()
declare -a RULE_BADS=()
declare -a RULE_GOODS=()
declare -a RULE_GREP_PATTERNS=()
# scope_dirs stored as colon-separated strings per rule
declare -a RULE_SCOPES=()

parse_rules() {
    local idx=-1
    local in_bad=0
    local in_good=0
    local in_scopes=0
    local bad_text=""
    local good_text=""
    local scopes_text=""

    while IFS= read -r line; do
        # Detect new rule block: "  - id: <value>"
        if [[ "$line" =~ ^[[:space:]]*-[[:space:]]+id:[[:space:]]*(.*) ]]; then
            # Flush previous rule's multiline fields
            if [[ $idx -ge 0 ]]; then
                RULE_BADS[$idx]="$bad_text"
                RULE_GOODS[$idx]="$good_text"
                RULE_SCOPES[$idx]="$scopes_text"
            fi
            idx=$((idx + 1))
            RULE_IDS[$idx]="${BASH_REMATCH[1]}"
            RULE_STATUSES[$idx]=""
            RULE_WHATS[$idx]=""
            RULE_GREP_PATTERNS[$idx]=""
            bad_text=""
            good_text=""
            scopes_text=""
            in_bad=0
            in_good=0
            in_scopes=0
            continue
        fi

        [[ $idx -lt 0 ]] && continue

        # End multiline block when hitting a new key at rule field level
        if [[ $in_bad -eq 1 ]]; then
            if [[ "$line" =~ ^[[:space:]]{4}[a-z_]+: ]] || [[ "$line" =~ ^[[:space:]]*-[[:space:]]+id: ]]; then
                in_bad=0
            else
                local stripped="${line#"${line%%[![:space:]]*}"}"
                [[ -n "$stripped" ]] && bad_text="${bad_text}      ${stripped}"$'\n'
                continue
            fi
        fi
        if [[ $in_good -eq 1 ]]; then
            if [[ "$line" =~ ^[[:space:]]{4}[a-z_]+: ]] || [[ "$line" =~ ^[[:space:]]*-[[:space:]]+id: ]]; then
                in_good=0
            else
                local stripped="${line#"${line%%[![:space:]]*}"}"
                [[ -n "$stripped" ]] && good_text="${good_text}      ${stripped}"$'\n'
                continue
            fi
        fi

        # Scope dirs list items: "      - "path/...""
        if [[ $in_scopes -eq 1 ]]; then
            if [[ "$line" =~ ^[[:space:]]+-[[:space:]]+[\"\']?([^\"\']+) ]]; then
                local dir="${BASH_REMATCH[1]}"
                dir="${dir%\"}"
                dir="${dir%\'}"
                [[ -n "$scopes_text" ]] && scopes_text="${scopes_text}:"
                scopes_text="${scopes_text}${dir}"
                continue
            else
                in_scopes=0
                # Fall through to check other field patterns
            fi
        fi

        # Field parsers
        if [[ "$line" =~ ^[[:space:]]+status:[[:space:]]*(.*) ]]; then
            RULE_STATUSES[$idx]="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]+what:[[:space:]]+[\"\'](.*)[\"\'] ]]; then
            RULE_WHATS[$idx]="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]+what:[[:space:]]+(.*) ]]; then
            RULE_WHATS[$idx]="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]+bad_example:[[:space:]]*\| ]]; then
            in_bad=1
        elif [[ "$line" =~ ^[[:space:]]+good_example:[[:space:]]*\| ]]; then
            in_good=1
        elif [[ "$line" =~ ^[[:space:]]+scope_dirs: ]]; then
            in_scopes=1
        elif [[ "$line" =~ ^[[:space:]]+grep_pattern:[[:space:]]+null ]]; then
            RULE_GREP_PATTERNS[$idx]=""
        elif [[ "$line" =~ ^[[:space:]]+grep_pattern:[[:space:]]+[\'\"](.+)[\'\"] ]]; then
            RULE_GREP_PATTERNS[$idx]="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]+grep_pattern:[[:space:]]+(.*) ]]; then
            local val="${BASH_REMATCH[1]}"
            [[ "$val" == "null" || "$val" == "~" ]] && val=""
            RULE_GREP_PATTERNS[$idx]="$val"
        fi
    done < "$RULES_FILE"

    # Flush final rule
    if [[ $idx -ge 0 ]]; then
        RULE_BADS[$idx]="$bad_text"
        RULE_GOODS[$idx]="$good_text"
        RULE_SCOPES[$idx]="$scopes_text"
    fi
}

parse_rules

RULE_COUNT=${#RULE_IDS[@]}
[[ $RULE_COUNT -eq 0 ]] && exit 0

# --- Check each rule against modified files ---
OUTPUT=""
ACTIVE_MATCH=0

for (( i=0; i<RULE_COUNT; i++ )); do
    local_status="${RULE_STATUSES[$i]}"

    # Skip disabled rules
    [[ "$local_status" == "disabled" ]] && continue

    # In CI mode, skip advisory rules
    [[ $CI_MODE -eq 1 && "$local_status" != "active" ]] && continue

    local_id="${RULE_IDS[$i]}"
    local_what="${RULE_WHATS[$i]}"
    local_bad="${RULE_BADS[$i]}"
    local_good="${RULE_GOODS[$i]}"
    local_grep="${RULE_GREP_PATTERNS[$i]}"
    local_scopes="${RULE_SCOPES[$i]}"

    # Skip rules with no scope dirs defined
    [[ -z "$local_scopes" ]] && continue

    # Convert colon-separated scopes to array
    IFS=':' read -ra scope_arr <<< "$local_scopes"

    while IFS= read -r mod_file; do
        [[ -z "$mod_file" ]] && continue

        # Check if file falls under any scope_dir
        in_scope=0
        for scope_dir in "${scope_arr[@]}"; do
            [[ -z "$scope_dir" ]] && continue
            if [[ "$mod_file" == "$scope_dir"* ]]; then
                in_scope=1
                break
            fi
        done
        [[ $in_scope -eq 0 ]] && continue

        # Semantic-only rules (null grep_pattern) rely on LLM review, not grep
        [[ -z "$local_grep" ]] && continue

        # Grep only changed/added lines to avoid flagging pre-existing code.
        # Uses git diff to extract added lines with their final line numbers.
        matches=$(git diff HEAD -- "$mod_file" 2>/dev/null \
            | awk '/^@@/{
                # Parse hunk header for the "new file" side: @@ -a,b +c,d @@
                match($0, /\+([0-9]+)/, m); line=m[1]-1; next
              }
              /^\+[^+]/{
                line++
                print line": "$0
                next
              }
              /^[^-]/{line++}' \
            | grep -E "$local_grep" 2>/dev/null || true)

        [[ -z "$matches" ]] && continue

        # Format label based on rule status
        local_label="ACTIVE"
        [[ "$local_status" == "advisory" ]] && local_label="ADVISORY"

        while IFS= read -r match_line; do
            [[ -z "$match_line" ]] && continue
            line_num="${match_line%%:*}"

            if [[ -z "$OUTPUT" ]]; then
                OUTPUT="REVIEW PATTERN CHECK:"$'\n'
            fi

            OUTPUT="${OUTPUT}"$'\n'
            OUTPUT="${OUTPUT}  [$local_label] $local_id in $mod_file:$line_num"$'\n'
            OUTPUT="${OUTPUT}    WHAT: $local_what"$'\n'

            if [[ -n "$local_bad" ]]; then
                OUTPUT="${OUTPUT}    BAD:"$'\n'
                OUTPUT="${OUTPUT}${local_bad}"
            fi
            if [[ -n "$local_good" ]]; then
                OUTPUT="${OUTPUT}    GOOD:"$'\n'
                OUTPUT="${OUTPUT}${local_good}"
            fi

            OUTPUT="${OUTPUT}    See: .claude/review-rules.yaml rule \"$local_id\""$'\n'

            if [[ "$local_status" == "advisory" ]]; then
                OUTPUT="${OUTPUT}    (advisory -- monitoring FP rate before promotion)"$'\n'
            fi

            [[ "$local_status" == "active" ]] && ACTIVE_MATCH=1
        done <<< "$matches"

    done <<< "$MODIFIED_FILES"
done

# --- Output results (only when matches found) ---
if [[ -n "$OUTPUT" ]]; then
    echo ""
    echo "$OUTPUT"
fi

# --- CI mode: exit 1 on active-rule match ---
if [[ $CI_MODE -eq 1 && $ACTIVE_MATCH -eq 1 ]]; then
    exit 1
fi

exit 0
