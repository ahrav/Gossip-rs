#!/usr/bin/env bash
# PGO build pipeline for Rust binaries.
# Handles instrumented build, profile collection, merge, and optimized build.
#
# Usage:
#   pgo_build.sh detect                          # Check toolchain availability
#   pgo_build.sh instrument <binary> [cargo-args] # Build instrumented binary
#   pgo_build.sh collect <binary> <args...>       # Run workload to collect profile
#   pgo_build.sh optimize <binary> [cargo-args]   # Build PGO-optimized binary
#   pgo_build.sh full <binary> <workload-cmd>     # Full pipeline in one shot
#
# Environment:
#   PGO_DATA_DIR  - Directory for profile data (default: /tmp/pgo-data-$$)
#   PGO_RUSTFLAGS - Extra RUSTFLAGS (default: "-C opt-level=3 -C target-cpu=native")

set -euo pipefail

PGO_DATA_DIR="${PGO_DATA_DIR:-/tmp/pgo-data-$$}"
PGO_RUSTFLAGS="${PGO_RUSTFLAGS:--C opt-level=3 -C target-cpu=native -C force-frame-pointers=yes -C debuginfo=2}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[pgo]${NC} $*"; }
ok()    { echo -e "${GREEN}[pgo]${NC} $*"; }
warn()  { echo -e "${YELLOW}[pgo]${NC} $*"; }
err()   { echo -e "${RED}[pgo]${NC} $*" >&2; }

# Find llvm-profdata in the Rust toolchain or system PATH
find_llvm_profdata() {
    if command -v llvm-profdata &>/dev/null; then
        echo "llvm-profdata"
        return 0
    fi

    local sysroot
    sysroot=$(rustc --print sysroot 2>/dev/null) || return 1
    local host
    host=$(rustc -vV 2>/dev/null | grep '^host:' | cut -d' ' -f2) || return 1
    local candidate="$sysroot/lib/rustlib/$host/bin/llvm-profdata"

    if [[ -x "$candidate" ]]; then
        echo "$candidate"
        return 0
    fi

    return 1
}

cmd_detect() {
    echo "=== PGO/BOLT Toolchain Detection ==="
    echo ""

    local os arch
    os=$(uname -s)
    arch=$(uname -m)
    echo "Platform: $os $arch"
    echo ""

    # Rust toolchain
    local rustc_ver
    rustc_ver=$(rustc --version 2>/dev/null || echo "NOT FOUND")
    echo "rustc:          $rustc_ver"

    # cargo-pgo
    if cargo pgo --version &>/dev/null 2>&1; then
        echo "cargo-pgo:      $(cargo pgo --version 2>&1 | head -1)"
    else
        echo "cargo-pgo:      MISSING (cargo install cargo-pgo)"
    fi

    # llvm-profdata
    local profdata
    if profdata=$(find_llvm_profdata); then
        echo "llvm-profdata:  $($profdata --version 2>&1 | head -1)"
    else
        echo "llvm-profdata:  MISSING (rustup component add llvm-tools-preview)"
    fi

    # hyperfine
    if command -v hyperfine &>/dev/null; then
        echo "hyperfine:      $(hyperfine --version 2>&1)"
    else
        echo "hyperfine:      MISSING (cargo install hyperfine)"
    fi

    echo ""

    # BOLT tools (Linux only)
    if [[ "$os" == "Linux" ]]; then
        echo "--- BOLT Tools (Linux) ---"

        if command -v llvm-bolt &>/dev/null; then
            echo "llvm-bolt:      $(llvm-bolt --version 2>&1 | head -1)"
        else
            echo "llvm-bolt:      MISSING (apt install llvm-bolt)"
        fi

        if command -v perf2bolt &>/dev/null; then
            echo "perf2bolt:      available"
        elif command -v llvm-profgen &>/dev/null; then
            echo "llvm-profgen:   available (alternative to perf2bolt)"
        else
            echo "perf2bolt:      MISSING"
        fi

        if command -v merge-fdata &>/dev/null; then
            echo "merge-fdata:    available"
        else
            echo "merge-fdata:    MISSING"
        fi

        if command -v perf &>/dev/null; then
            echo "perf:           $(perf version 2>&1 | head -1)"
        else
            echo "perf:           MISSING (apt install linux-tools-$(uname -r))"
        fi

        echo ""
    else
        echo "--- BOLT: Not available (requires Linux ELF binaries) ---"
        echo ""
    fi

    # Pipeline recommendation
    echo "=== Recommended Pipeline ==="
    if [[ "$os" == "Linux" ]]; then
        if command -v llvm-bolt &>/dev/null && command -v perf &>/dev/null; then
            ok "Full PGO + BOLT pipeline available"
        elif profdata=$(find_llvm_profdata); then
            warn "PGO available, BOLT missing — install llvm-bolt for full pipeline"
        else
            err "Missing tools — install llvm-tools-preview and llvm-bolt"
        fi
    else
        if profdata=$(find_llvm_profdata); then
            ok "PGO-only pipeline available (BOLT requires Linux)"
        else
            err "Missing llvm-tools-preview — run: rustup component add llvm-tools-preview"
        fi
    fi
}

cmd_instrument() {
    local binary="${1:?Usage: pgo_build.sh instrument <binary> [cargo-args...]}"
    shift

    mkdir -p "$PGO_DATA_DIR"
    info "Instrumented build: $binary (profile data -> $PGO_DATA_DIR)"

    RUSTFLAGS="$PGO_RUSTFLAGS -Cprofile-generate=$PGO_DATA_DIR" \
        cargo build --release --bin "$binary" "$@"

    ok "Instrumented binary built. Run workloads to collect profiles."
    echo "  Next: pgo_build.sh collect $binary <workload_args>"
}

cmd_collect() {
    local binary="${1:?Usage: pgo_build.sh collect <binary> <args...>}"
    shift

    local target_triple
    target_triple=$(rustc -vV | grep '^host:' | cut -d' ' -f2)
    local bin_path="./target/${target_triple}/release/$binary"

    # Fall back to standard release path if target-triple path doesn't exist
    if [[ ! -x "$bin_path" ]]; then
        bin_path="./target/release/$binary"
    fi

    if [[ ! -x "$bin_path" ]]; then
        err "Binary not found at expected paths. Build with 'instrument' first."
        exit 1
    fi

    info "Running workload: $bin_path $*"
    LLVM_PROFILE_FILE="$PGO_DATA_DIR/run-%p-%m.profraw" "$bin_path" "$@"

    local count
    count=$(find "$PGO_DATA_DIR" -name '*.profraw' 2>/dev/null | wc -l)
    ok "Profile collected. Total .profraw files: $count"
}

cmd_optimize() {
    local binary="${1:?Usage: pgo_build.sh optimize <binary> [cargo-args...]}"
    shift

    local profdata
    profdata=$(find_llvm_profdata) || {
        err "llvm-profdata not found. Run: rustup component add llvm-tools-preview"
        exit 1
    }

    # Merge profiles
    local profraw_count
    profraw_count=$(find "$PGO_DATA_DIR" -name '*.profraw' 2>/dev/null | wc -l)
    if [[ "$profraw_count" -eq 0 ]]; then
        err "No .profraw files in $PGO_DATA_DIR. Run workloads with 'collect' first."
        exit 1
    fi

    info "Merging $profraw_count profile(s)..."
    "$profdata" merge -o "$PGO_DATA_DIR/merged.profdata" "$PGO_DATA_DIR"/*.profraw

    # Show profile summary
    info "Profile summary:"
    "$profdata" show "$PGO_DATA_DIR/merged.profdata" --counts --all-functions 2>&1 | head -10

    # PGO-optimized build
    info "Building PGO-optimized binary: $binary"
    RUSTFLAGS="$PGO_RUSTFLAGS -Cprofile-use=$PGO_DATA_DIR/merged.profdata -Cllvm-args=-pgo-warn-missing-function" \
        cargo build --release --bin "$binary" "$@"

    ok "PGO-optimized binary built at ./target/release/$binary"
}

cmd_full() {
    local binary="${1:?Usage: pgo_build.sh full <binary> <workload-cmd>}"
    local workload="${2:?Usage: pgo_build.sh full <binary> <workload-cmd>}"

    info "=== Full PGO Pipeline ==="
    info "Binary: $binary"
    info "Workload: $workload"
    info "Profile dir: $PGO_DATA_DIR"
    echo ""

    cmd_instrument "$binary"
    echo ""

    info "Running workload 3 times for profile diversity..."
    for i in 1 2 3; do
        info "Run $i/3..."
        eval "LLVM_PROFILE_FILE='$PGO_DATA_DIR/run-$i-%p-%m.profraw' $workload" || true
    done
    echo ""

    cmd_optimize "$binary"
    echo ""

    ok "=== PGO Pipeline Complete ==="
    echo "  Baseline: save current binary before re-running"
    echo "  Compare:  hyperfine './target/release/$binary.baseline <args>' './target/release/$binary <args>'"
}

# Dispatch
case "${1:-help}" in
    detect)     cmd_detect ;;
    instrument) shift; cmd_instrument "$@" ;;
    collect)    shift; cmd_collect "$@" ;;
    optimize)   shift; cmd_optimize "$@" ;;
    full)       shift; cmd_full "$@" ;;
    help|*)
        echo "PGO Build Pipeline for Rust"
        echo ""
        echo "Usage:"
        echo "  pgo_build.sh detect                          # Check toolchain"
        echo "  pgo_build.sh instrument <binary> [cargo-args] # Instrumented build"
        echo "  pgo_build.sh collect <binary> <args...>       # Collect profile"
        echo "  pgo_build.sh optimize <binary> [cargo-args]   # PGO-optimized build"
        echo "  pgo_build.sh full <binary> <workload-cmd>     # Full pipeline"
        echo ""
        echo "Environment:"
        echo "  PGO_DATA_DIR  - Profile data directory (default: /tmp/pgo-data-PID)"
        echo "  PGO_RUSTFLAGS - Extra RUSTFLAGS"
        ;;
esac
