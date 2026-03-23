#!/bin/bash
# Pre-flight checks for causal profiling with coz.
#
# Usage:
#   ./causal_preflight.sh <binary>
#
# Verifies: platform, coz installation, debug info, perf_event access,
# and feature flag presence.

set -euo pipefail

BINARY="${1:-}"

if [ -z "$BINARY" ]; then
    echo "Usage: causal_preflight.sh <binary>"
    echo ""
    echo "Example:"
    echo "  ./causal_preflight.sh ./target/causal/my-binary"
    exit 1
fi

PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
warn() { echo "  [WARN] $1"; WARN=$((WARN + 1)); }

echo "=== Causal Profiling Pre-Flight Checks ==="
echo "Binary: $BINARY"
echo ""

# 1. Platform check
echo "--- Platform ---"
OS=$(uname -s)
if [ "$OS" = "Linux" ]; then
    pass "Running on Linux"
else
    fail "Running on $OS — coz requires Linux (LD_PRELOAD + perf_event_open)"
    echo "        Suggestion: Use Docker with --cap-add CAP_PERFMON --cap-add SYS_PTRACE"
fi

# 2. coz installation
echo "--- coz Installation ---"
if command -v coz &> /dev/null; then
    COZ_VERSION=$(coz --version 2>/dev/null || echo "unknown")
    pass "coz found: $COZ_VERSION"
else
    fail "coz not found in PATH"
    echo "        Install: apt-get install coz-profiler"
    echo "        Or build from source: https://github.com/plasma-umass/coz"
fi

# 3. Binary exists
echo "--- Binary ---"
if [ -f "$BINARY" ]; then
    pass "Binary exists: $BINARY"
else
    fail "Binary not found: $BINARY"
    echo "        Build with: cargo build --profile causal --features causal-profiling"
    echo ""
    echo "=== Pre-flight FAILED (binary not found, skipping remaining checks) ==="
    exit 1
fi

# 4. Debug info
echo "--- Debug Info ---"
if command -v readelf &> /dev/null; then
    if readelf -S "$BINARY" 2>/dev/null | grep -q 'debug_line'; then
        pass "Binary has .debug_line section"
    else
        fail "Binary missing .debug_line section — profiles will be empty"
        echo "        Fix: Add [profile.causal] with debug = 1 to workspace Cargo.toml"
    fi

    if readelf -S "$BINARY" 2>/dev/null | grep -q 'debug_info'; then
        pass "Binary has .debug_info section (full DWARF)"
    else
        warn "Binary missing .debug_info — using line tables only (debug = 1)"
        echo "        For better line attribution, use debug = 2"
    fi
else
    warn "readelf not found — cannot verify debug info"
fi

# 5. perf_event access
echo "--- perf_event Access ---"
if [ -f /proc/sys/kernel/perf_event_paranoid ]; then
    PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid)
    if [ "$PARANOID" -le 1 ]; then
        pass "perf_event_paranoid = $PARANOID (accessible)"
    elif [ "$PARANOID" -le 2 ]; then
        warn "perf_event_paranoid = $PARANOID (may need root)"
        echo "        Fix: echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
    else
        fail "perf_event_paranoid = $PARANOID (too restrictive)"
        echo "        Fix: echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid"
    fi
else
    warn "Cannot read /proc/sys/kernel/perf_event_paranoid (not on Linux or no procfs)"
fi

# 6. Feature flag in workspace
echo "--- Feature Gate ---"
# Search upward for workspace Cargo.toml
SEARCH_DIR=$(dirname "$(realpath "$BINARY")")
WORKSPACE_TOML=""
while [ "$SEARCH_DIR" != "/" ]; do
    if [ -f "$SEARCH_DIR/Cargo.toml" ] && grep -q '\[workspace\]' "$SEARCH_DIR/Cargo.toml" 2>/dev/null; then
        WORKSPACE_TOML="$SEARCH_DIR/Cargo.toml"
        break
    fi
    SEARCH_DIR=$(dirname "$SEARCH_DIR")
done

if [ -n "$WORKSPACE_TOML" ]; then
    if grep -q 'profile.causal' "$WORKSPACE_TOML" 2>/dev/null; then
        pass "[profile.causal] found in $WORKSPACE_TOML"
    else
        warn "[profile.causal] not found in $WORKSPACE_TOML"
        echo "        Add: [profile.causal] with inherits = \"release\" and debug = 1"
    fi
fi

# Search for causal-profiling feature in any crate Cargo.toml
FOUND_FEATURE=false
if [ -n "$WORKSPACE_TOML" ]; then
    WS_DIR=$(dirname "$WORKSPACE_TOML")
    while IFS= read -r -d '' toml; do
        if grep -q 'causal-profiling' "$toml" 2>/dev/null; then
            FOUND_FEATURE=true
            break
        fi
    done < <(find "$WS_DIR" -name Cargo.toml -print0 2>/dev/null)
fi

if [ "$FOUND_FEATURE" = true ]; then
    pass "causal-profiling feature found in workspace"
else
    warn "causal-profiling feature not found in any Cargo.toml"
    echo "        Add to target crate: [features] causal-profiling = [\"dep:coz\"]"
fi

# 7. coz crate source check
echo "--- coz Crate Source ---"
if [ -n "$WORKSPACE_TOML" ]; then
    WS_DIR=$(dirname "$WORKSPACE_TOML")
    if grep -rq 'coz.*crates\.io' "$WS_DIR"/Cargo.lock 2>/dev/null; then
        warn "coz crate appears to come from crates.io — v0.1.3 has a critical bug"
        echo "        Fix: Use git master: coz = { git = \"https://github.com/plasma-umass/coz.git\" }"
    elif grep -rq 'coz.*github' "$WS_DIR"/Cargo.lock 2>/dev/null; then
        pass "coz crate sourced from git (not affected by v0.1.3 bug)"
    else
        warn "Could not determine coz crate source from Cargo.lock"
    fi
fi

# Summary
echo ""
echo "=== Summary ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Warnings: $WARN"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "=== Pre-flight FAILED — fix the above issues before profiling ==="
    exit 1
elif [ "$WARN" -gt 0 ]; then
    echo "=== Pre-flight PASSED with warnings — review before profiling ==="
    exit 0
else
    echo "=== Pre-flight PASSED — ready to profile ==="
    exit 0
fi
