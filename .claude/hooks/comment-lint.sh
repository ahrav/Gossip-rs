#!/bin/bash
#
# comment-lint.sh — Enforces the project comment policy on .rs and .md files.
#
# Scans Rust source files for comments that contain tracking IDs, PR references,
# review-response language, temporal/history narration, or conversational tone.
# Scans Markdown files (docs/, diagrams/) for milestone/phase tracking and
# task-management references.
#
# These belong in PR descriptions, issue trackers, or commit messages — not in
# source code or documentation.
#
# Runs as a PostToolUse hook on Edit|Write operations.
#
# Environment variables (from Claude Code):
#   CLAUDE_FILE_PATH  - Absolute path to the file that was edited
#
# Exit codes:
#   0 - Always (hook should not block; violations are reported via stdout)

set -euo pipefail

FILE_PATH="${CLAUDE_FILE_PATH:-}"

[[ -z "$FILE_PATH" ]] && exit 0
[[ ! -f "$FILE_PATH" ]] && exit 0

# --- Determine file type and extract scannable lines ---
IS_RUST=false
IS_MD=false

if [[ "$FILE_PATH" == *.rs ]]; then
    IS_RUST=true
    # Extract comment lines with line numbers
    # Matches lines whose first non-whitespace content is // or /// or //!
    # Also matches trailing comments after code (stuff // comment)
    comments=$(grep -nE '(^\s*//|//[!/]?\s)' "$FILE_PATH" 2>/dev/null || true)
    [[ -z "$comments" ]] && exit 0
elif [[ "$FILE_PATH" == *.md ]]; then
    # Only lint docs/ and diagrams/ markdown files
    case "$FILE_PATH" in
        */docs/*|*/diagrams/*) IS_MD=true ;;
        *) exit 0 ;;
    esac
    # Scan all non-empty lines (prose content)
    comments=$(grep -n '.' "$FILE_PATH" 2>/dev/null || true)
    [[ -z "$comments" ]] && exit 0
else
    exit 0
fi

VIOLATIONS=()

check_pattern() {
    local pattern="$1"
    local category="$2"

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        local linenum="${match%%:*}"
        local text="${match#*:}"
        VIOLATIONS+=("  Line $linenum [$category]: $text")
    done < <(echo "$comments" | grep -iE "$pattern" 2>/dev/null || true)
}

# --- Milestone / phase tracking labels ---
# "B0" is never a boundary name (boundaries are B1-B5), so it always
# indicates a task milestone reference.
# In .rs files B1-B5 are also flagged: code comments should use crate or
# trait names (e.g. "gossip-coordination", "CoordinationBackend"), not
# boundary shorthand labels.
# In .md docs B1-B5 are legitimate architectural boundary names and are
# not flagged.
if $IS_RUST; then
    check_pattern '\bB[0-9]\b' "milestone tracking"
elif $IS_MD; then
    # Match B0 in prose context (preceded by whitespace or start-of-line).
    # This avoids false positives in array/list labels like [B0, B1, ...].
    check_pattern '(^|[[:space:]])B0\b' "milestone tracking"
fi

# --- Markdown: beads task IDs and step tracking refs ---
if $IS_MD; then
    check_pattern 'gossip-[0-9]{4}' "beads task ID"
    check_pattern 'gossip-rs-[0-9a-z]+\.[0-9]' "step tracking ref"
fi

# --- Rust-only checks (too broad for .md prose) ---
if $IS_RUST; then

# --- Finding/tracking ID prefixes in comments ---
# Patterns like "F-011:", "F7:", "C3:", "H9:", "P0:" used as comment labels
check_pattern '//[!/]?\s*(F-?[0-9]{1,3})\b' "tracking ID"

# --- PR / merge request references ---
check_pattern 'PR\s*#[0-9]|PR-[0-9]|pull request|merge request' "PR reference"

# --- Review-response language ---
check_pattern 'per review|reviewer feedback|review comment|review finding' "review response"
check_pattern 'addressed.*(feedback|comment|finding|concern)' "review response"
check_pattern 'as requested by|suggested by reviewer' "review response"
check_pattern 'added (to |for )?(cover|address|fix).*(review|finding|comment|feedback)' "review response"
check_pattern 'verification tests? for (PR|review|finding)' "review response"
check_pattern 'test.* added.* (for|from|per) .*(finding|review|PR|comment)' "review response"

# --- Temporal / history narration ---
# NOTE: "previously (used|was|had)" may false-positive on runtime-behavior
# descriptions like "the OpId was previously used with a different payload".
# The agent should evaluate context: if the comment describes RUNTIME state
# (what happens at execution time), it's fine. If it describes CODE history
# (what the code looked like before a change), it's a violation.
check_pattern 'was changed from|previously (used|was|had)|used to be' "temporal narration"
check_pattern 'refactored from|moved from .* to' "temporal narration"
check_pattern 'new(ly)? (added|introduced|created)' "temporal narration"

# --- Bug-fix / change-history narration ---
# Comments should describe invariants, not narrate what broke or what was fixed.
check_pattern '(without|before|after) the (fix|change|patch|refactor)' "fix-history narration"
check_pattern 'the old \w+\(\)|the old (implementation|version|approach)' "fix-history narration"
check_pattern 'this was the bug|this is the bug|that was the bug' "fix-history narration"
check_pattern "(didn|did not|didn't).* catch (this|that|the)" "fix-history narration"
check_pattern 'reintroduce[sd]? the bug|reintroduce[sd]? the (issue|problem)' "fix-history narration"
check_pattern 'with the fix,|after fixing' "fix-history narration"

# --- Task-management language in section headers ---
# "coverage gap" in a domain sense (shard coverage) is fine; flag only
# when it appears as a standalone section label (line ends after the phrase).
check_pattern '//\s*(coverage gap tests?|test gap|gap coverage)\s*$' "task-management label"
check_pattern '(high|medium|low)-priority (test|coverage|fix)' "task-management label"
check_pattern 'gap.?filling' "task-management label"

# --- Conversational tone ---
check_pattern 'good catch|as discussed|note to reviewer' "conversational"
check_pattern 'per (our|the) conversation' "conversational"

fi  # end IS_RUST

# --- Output violations ---
if [[ ${#VIOLATIONS[@]} -gt 0 ]]; then
    echo ""
    if $IS_RUST; then
        echo "COMMENT POLICY VIOLATION in $(basename "$FILE_PATH"):"
        echo "  Comments must describe code behavior, not reference tracking systems,"
        echo "  PR discussions, review findings, milestone phases, or change history."
    else
        echo "COMMENT POLICY VIOLATION in $(basename "$FILE_PATH"):"
        echo "  Documentation must not reference internal tracking systems, milestone"
        echo "  phases (B0/B1/B2), task IDs, PR discussions, or change history."
    fi
    echo ""
    for v in "${VIOLATIONS[@]}"; do
        echo "$v"
    done
    echo ""
    echo "  Fix: Rewrite each flagged line to describe WHAT the code/system does"
    echo "  or WHY from a design/correctness perspective. Remove all tracking"
    echo "  IDs, milestone labels, PR references, and review-response language."
    echo ""
fi

exit 0
