#!/bin/bash
#
# design-doc-scope-check.sh - Reminds agents to check design docs when editing
# files in documented directories.
#
# Reads docs/scope-map.toml to determine which design docs cover which
# source directories, then fires one of three alerts:
#   - Existing file in scope: reminder to verify design doc still matches code
#   - New file in scope:      stronger alert — doc's file list may need updating
#   - Uncovered file:         note that no design doc covers this path
#
# Environment variables (from Claude Code):
#   CLAUDE_FILE_PATH  - Absolute path to the file that was edited
#   CLAUDE_SESSION_ID - Session identifier (optional, falls back to $$)
#
# Exit codes:
#   0 - Always (hook should not block)

set -euo pipefail

FILE_PATH="${CLAUDE_FILE_PATH:-}"

# --- Guard: skip non-.rs files ---
[[ -z "$FILE_PATH" ]] && exit 0
[[ "$FILE_PATH" != *.rs ]] && exit 0

# --- Locate repo root and scope map ---
REPO_ROOT=""
if command -v git &>/dev/null; then
    REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
fi
[[ -z "$REPO_ROOT" ]] && exit 0

SCOPE_MAP="$REPO_ROOT/docs/scope-map.toml"
[[ ! -f "$SCOPE_MAP" ]] && exit 0

# --- Resolve repo-relative path ---
# Strip repo root prefix to get e.g. "crates/gossip-contracts/src/identity/foo.rs"
REL_PATH="${FILE_PATH#"$REPO_ROOT"/}"
# If stripping didn't change anything, file is outside the repo
[[ "$REL_PATH" == "$FILE_PATH" ]] && exit 0

# --- Session dedup tracker ---
SESSION_ID="${CLAUDE_SESSION_ID:-$$}"
DEDUP_FILE="/tmp/claude-scope-check-$SESSION_ID"

already_reminded() {
    local key="$1"
    [[ -f "$DEDUP_FILE" ]] && grep -qFx "$key" "$DEDUP_FILE" 2>/dev/null
}

mark_reminded() {
    local key="$1"
    echo "$key" >> "$DEDUP_FILE"
}

# --- Detect new file (not yet tracked by git) ---
IS_NEW_FILE=0
if command -v git &>/dev/null && git rev-parse --git-dir &>/dev/null 2>&1; then
    if ! git ls-files --error-unmatch "$FILE_PATH" &>/dev/null 2>&1; then
        IS_NEW_FILE=1
    fi
fi

# --- Parse scope-map.toml and check matches ---
# We parse the TOML with simple line-by-line state machine.
# Format is strictly: [[scopes]] blocks with doc = "..." and dir = "..." lines.
MATCHED_DOCS=()
current_doc=""
current_dir=""

while IFS= read -r line; do
    # Strip leading/trailing whitespace
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"

    # Skip empty lines and comments
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue

    # New scope block resets state
    if [[ "$line" == "[[scopes]]" ]]; then
        # Process previous block if complete
        if [[ -n "$current_doc" && -n "$current_dir" ]]; then
            if [[ "$REL_PATH" == "$current_dir"* ]]; then
                MATCHED_DOCS+=("$current_doc")
            fi
        fi
        current_doc=""
        current_dir=""
        continue
    fi

    # Parse doc = "..."
    if [[ "$line" == doc\ =\ * ]]; then
        current_doc="${line#doc = \"}"
        current_doc="${current_doc%\"}"
        continue
    fi

    # Parse dir = "..."
    if [[ "$line" == dir\ =\ * ]]; then
        current_dir="${line#dir = \"}"
        current_dir="${current_dir%\"}"
        continue
    fi
done < "$SCOPE_MAP"

# Process final block
if [[ -n "$current_doc" && -n "$current_dir" ]]; then
    if [[ "$REL_PATH" == "$current_dir"* ]]; then
        MATCHED_DOCS+=("$current_doc")
    fi
fi

# --- Deduplicate matched docs ---
UNIQUE_DOCS=()
for doc in "${MATCHED_DOCS[@]+"${MATCHED_DOCS[@]}"}"; do
    is_dup=0
    for seen in "${UNIQUE_DOCS[@]+"${UNIQUE_DOCS[@]}"}"; do
        if [[ "$doc" == "$seen" ]]; then
            is_dup=1
            break
        fi
    done
    [[ $is_dup -eq 0 ]] && UNIQUE_DOCS+=("$doc")
done

# --- Output alerts ---
if [[ ${#UNIQUE_DOCS[@]} -gt 0 ]]; then
    for doc in "${UNIQUE_DOCS[@]}"; do
        if [[ $IS_NEW_FILE -eq 1 ]]; then
            # New file alerts always fire (bypass dedup) — rare and high-priority
            echo "DESIGN DOC CHECK [NEW FILE]: $REL_PATH is NEW and in scope of:"
            echo "  -> $doc"
        else
            # Existing file: once per doc per session
            dedup_key="doc:$doc"
            if ! already_reminded "$dedup_key"; then
                echo "DESIGN DOC CHECK: $REL_PATH is in scope of:"
                echo "  -> $doc"
                mark_reminded "$dedup_key"
            fi
        fi
    done
    exit 0
fi

# --- No scope matched: check exclusion list before alerting ---

# Exclusion patterns (files that don't trigger "uncovered" alert)
# Test files
[[ "$REL_PATH" == *_test.rs ]] && exit 0
[[ "$REL_PATH" == *_tests.rs ]] && exit 0
[[ "$REL_PATH" == */tests/* ]] && exit 0

# Bench/fuzz files
[[ "$REL_PATH" == */benches/* ]] && exit 0
[[ "$REL_PATH" == */fuzz/* ]] && exit 0
[[ "$REL_PATH" == */fuzz_targets/* ]] && exit 0

# Crate root files
[[ "$REL_PATH" == crates/*/src/lib.rs ]] && exit 0
[[ "$REL_PATH" == crates/*/src/main.rs ]] && exit 0

# Utility crate (not architecture-critical)
[[ "$REL_PATH" == crates/gossip-stdx/* ]] && exit 0

# Build scripts and proptest regressions
[[ "$REL_PATH" == */build.rs ]] && exit 0
[[ "$REL_PATH" == */proptest-regressions/* ]] && exit 0

# --- Uncovered file alert (once per file per session) ---
dedup_key="uncovered:$REL_PATH"
if ! already_reminded "$dedup_key"; then
    echo "NOTE: $REL_PATH has no design doc coverage."
    mark_reminded "$dedup_key"
fi

exit 0
