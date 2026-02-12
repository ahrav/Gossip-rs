#!/bin/bash
#
# doc-rigor-gate.sh - Determines if doc-rigor skill should run after code changes
#
# This script analyzes the changed file and outputs a suggestion when
# documentation review is warranted. It runs as a PostToolUse hook.
#
# Environment variables (from Claude Code):
#   CLAUDE_FILE_PATH - Path to the file that was edited
#
# Exit codes:
#   0 - Always (hook should not block)
#
# Output:
#   Prints recommendation message to stdout when doc-rigor is warranted

set -euo pipefail

FILE_PATH="${CLAUDE_FILE_PATH:-}"

# Skip if no file path or not a Rust file
[[ -z "$FILE_PATH" ]] && exit 0
[[ "$FILE_PATH" != *.rs ]] && exit 0

# Skip test files - they don't need doc-rigor
[[ "$FILE_PATH" == *_test.rs ]] && exit 0
[[ "$FILE_PATH" == *_tests.rs ]] && exit 0
[[ "$FILE_PATH" == */tests/* ]] && exit 0

# Skip rule definition files (YAML rules, rule loader)
[[ "$FILE_PATH" == *default_rules.yaml ]] && exit 0

# Track cumulative changes in a session temp file
SESSION_TRACKER="/tmp/claude-doc-rigor-$$"
if [[ -n "${CLAUDE_SESSION_ID:-}" ]]; then
    SESSION_TRACKER="/tmp/claude-doc-rigor-${CLAUDE_SESSION_ID}"
fi

# Initialize or read current state
if [[ -f "$SESSION_TRACKER" ]]; then
    source "$SESSION_TRACKER"
else
    TOTAL_LINES_CHANGED=0
    FILES_CHANGED=""
    PUBLIC_API_TOUCHED=0
fi

# Analyze the current file for significance markers
analyze_file() {
    local file="$1"
    local score=0
    local reasons=()

    [[ ! -f "$file" ]] && echo "0" && return

    # Check for public API definitions (high value for doc-rigor)
    local pub_count
    pub_count=$(grep -cE '^\s*pub\s+(fn|struct|enum|trait|type|const|static|mod)\s+' "$file" 2>/dev/null || echo 0)
    if [[ $pub_count -gt 0 ]]; then
        score=$((score + pub_count * 3))
        reasons+=("$pub_count public items")
    fi

    # Check for unsafe blocks (always warrant documentation)
    if grep -qE 'unsafe\s*\{|unsafe\s+fn|unsafe\s+impl' "$file" 2>/dev/null; then
        score=$((score + 10))
        reasons+=("unsafe code")
    fi

    # Check for complex generic signatures
    local generic_count
    generic_count=$(grep -cE '<[A-Z][^>]*>' "$file" 2>/dev/null || echo 0)
    if [[ $generic_count -gt 3 ]]; then
        score=$((score + 2))
        reasons+=("complex generics")
    fi

    # Check for trait implementations
    local impl_count
    impl_count=$(grep -cE '^\s*impl\s+' "$file" 2>/dev/null || echo 0)
    if [[ $impl_count -gt 2 ]]; then
        score=$((score + impl_count))
        reasons+=("$impl_count impl blocks")
    fi

    # Critical paths get higher weight
    if [[ "$file" == *src/engine/* ]]; then
        score=$((score + 5))
        reasons+=("engine core path")
    fi
    if [[ "$file" == *src/api* ]]; then
        score=$((score + 5))
        reasons+=("public API")
    fi

    # Output score for threshold comparison
    echo "$score"
}

# Get lines changed in this file (staged + unstaged)
get_lines_changed() {
    local file="$1"
    local lines=0

    if command -v git &>/dev/null && git rev-parse --git-dir &>/dev/null 2>&1; then
        # Count changed lines from git diff (additions + deletions)
        lines=$(git diff --numstat -- "$file" 2>/dev/null | awk '{print $1 + $2}' || echo 0)
        # Also include staged changes
        local staged
        staged=$(git diff --cached --numstat -- "$file" 2>/dev/null | awk '{print $1 + $2}' || echo 0)
        lines=$((lines + staged))
    fi

    echo "${lines:-0}"
}

# Calculate significance
FILE_SCORE=$(analyze_file "$FILE_PATH")
LINES_CHANGED=$(get_lines_changed "$FILE_PATH")
TOTAL_LINES_CHANGED=$((TOTAL_LINES_CHANGED + LINES_CHANGED))

# Track files changed
if [[ ! "$FILES_CHANGED" == *"$FILE_PATH"* ]]; then
    FILES_CHANGED="${FILES_CHANGED}${FILE_PATH}:"
fi
FILE_COUNT=$(echo "$FILES_CHANGED" | tr ':' '\n' | grep -c . || echo 0)

# Check if public APIs were touched
if grep -qE '^\s*pub\s+(fn|struct|enum|trait)' "$FILE_PATH" 2>/dev/null; then
    PUBLIC_API_TOUCHED=1
fi

# Save state for cumulative tracking
cat > "$SESSION_TRACKER" << EOF
TOTAL_LINES_CHANGED=$TOTAL_LINES_CHANGED
FILES_CHANGED="$FILES_CHANGED"
PUBLIC_API_TOUCHED=$PUBLIC_API_TOUCHED
EOF

# Decision thresholds
SCORE_THRESHOLD=8        # Complexity/significance score
LINES_THRESHOLD=50       # Cumulative lines changed
MULTI_FILE_THRESHOLD=3   # Number of source files changed

# Determine if doc-rigor should run
SHOULD_RUN=0
REASON=""

if [[ $FILE_SCORE -ge $SCORE_THRESHOLD ]]; then
    SHOULD_RUN=1
    REASON="significant code complexity (score: $FILE_SCORE)"
elif [[ $TOTAL_LINES_CHANGED -ge $LINES_THRESHOLD ]]; then
    SHOULD_RUN=1
    REASON="substantial changes ($TOTAL_LINES_CHANGED lines across session)"
elif [[ $FILE_COUNT -ge $MULTI_FILE_THRESHOLD && $PUBLIC_API_TOUCHED -eq 1 ]]; then
    SHOULD_RUN=1
    REASON="multi-file changes touching public APIs ($FILE_COUNT files)"
fi

# Output recommendation if warranted
if [[ $SHOULD_RUN -eq 1 ]]; then
    echo ""
    echo "📝 DOC-RIGOR RECOMMENDED: $REASON"
    echo "   Consider running /doc-rigor on modified code to ensure documentation quality."
    echo ""
fi

exit 0
