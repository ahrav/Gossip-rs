#!/usr/bin/env bash
# BOLT post-link optimization pipeline for Rust binaries.
# Collects branch profiles and reorders binary layout for I-cache and BTB wins.
#
# Usage:
#   bolt_optimize.sh profile <binary> <args...>   # Collect branch profile via perf
#   bolt_optimize.sh convert <binary>              # Convert perf data to BOLT fdata
#   bolt_optimize.sh apply <binary>                # Apply BOLT optimizations
#   bolt_optimize.sh full <binary> <args...>       # Full pipeline in one shot
#
# Environment:
#   BOLT_DATA_DIR   - Directory for BOLT data (default: /tmp/bolt-data-$$)
#   BOLT_EXTRA_FLAGS - Additional llvm-bolt flags
#   PERF_SAMPLE_RATE - Branch sample period (default: 100003)

set -euo pipefail

BOLT_DATA_DIR="${BOLT_DATA_DIR:-/tmp/bolt-data-$$}"
BOLT_EXTRA_FLAGS="${BOLT_EXTRA_FLAGS:-}"
PERF_SAMPLE_RATE="${PERF_SAMPLE_RATE:-100003}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[bolt]${NC} $*"; }
ok()    { echo -e "${GREEN}[bolt]${NC} $*"; }
warn()  { echo -e "${YELLOW}[bolt]${NC} $*"; }
err()   { echo -e "${RED}[bolt]${NC} $*" >&2; }

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) echo "unknown" ;;
    esac
}

detect_cpu_vendor() {
    if [[ -f /proc/cpuinfo ]]; then
        if grep -qi 'GenuineIntel' /proc/cpuinfo; then
            echo "intel"
        elif grep -qi 'AuthenticAMD' /proc/cpuinfo; then
            echo "amd"
        else
            echo "unknown"
        fi
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        echo "apple"
    else
        echo "unknown"
    fi
}

# Select perf event based on architecture and CPU vendor
select_perf_event() {
    local arch vendor
    arch=$(detect_arch)
    vendor=$(detect_cpu_vendor)

    case "$arch" in
        x86_64)
            case "$vendor" in
                intel)
                    # Intel LBR: precise taken-branch sampling
                    echo "br_inst_retired.near_taken:upp"
                    ;;
                amd)
                    # AMD: try IBS first, fall back to generic branches
                    if perf list 2>/dev/null | grep -q 'ibs_op'; then
                        echo "ibs_op//"
                    else
                        echo "branches:u"
                    fi
                    ;;
                *)
                    echo "branches:u"
                    ;;
            esac
            ;;
        aarch64)
            # ARM SPE for branch profiling (requires kernel support)
            if perf list 2>/dev/null | grep -q 'arm_spe'; then
                echo "arm_spe_0/branch_filter=1,min_latency=0/"
            else
                warn "ARM SPE not available. Using generic branch event."
                echo "branches:u"
            fi
            ;;
        *)
            echo "branches:u"
            ;;
    esac
}

cmd_profile() {
    local binary="${1:?Usage: bolt_optimize.sh profile <binary> <args...>}"
    shift

    if [[ "$(uname -s)" != "Linux" ]]; then
        err "BOLT profile collection requires Linux (perf). Exiting."
        exit 1
    fi

    if ! command -v perf &>/dev/null; then
        err "perf not found. Install: apt install linux-tools-\$(uname -r)"
        exit 1
    fi

    mkdir -p "$BOLT_DATA_DIR"

    local perf_event
    perf_event=$(select_perf_event)
    local arch
    arch=$(detect_arch)
    local vendor
    vendor=$(detect_cpu_vendor)

    info "Architecture: $arch ($vendor)"
    info "Perf event: $perf_event"
    info "Sample rate: every $PERF_SAMPLE_RATE events"
    info "Binary: $binary"
    info "Args: $*"
    echo ""

    info "Recording branch profile..."
    sudo perf record \
        -o "$BOLT_DATA_DIR/perf.data" \
        -e "$perf_event" \
        -b \
        -c "$PERF_SAMPLE_RATE" \
        -- "$binary" "$@"

    local sample_count
    sample_count=$(perf report -i "$BOLT_DATA_DIR/perf.data" --stdio 2>&1 | grep -c 'Event count' || echo "unknown")
    ok "Profile collected: $BOLT_DATA_DIR/perf.data"
    info "Run 'bolt_optimize.sh convert <binary>' to convert to BOLT format."
}

cmd_convert() {
    local binary="${1:?Usage: bolt_optimize.sh convert <binary>}"

    if [[ ! -f "$BOLT_DATA_DIR/perf.data" ]]; then
        err "No perf.data found in $BOLT_DATA_DIR. Run 'profile' first."
        exit 1
    fi

    info "Converting perf data to BOLT fdata format..."

    if command -v perf2bolt &>/dev/null; then
        # Preferred: direct perf2bolt conversion
        info "Using perf2bolt (direct conversion)..."
        perf2bolt \
            -p "$BOLT_DATA_DIR/perf.data" \
            -o "$BOLT_DATA_DIR/perf.fdata" \
            "$binary"
    elif command -v llvm-profgen &>/dev/null; then
        # Fallback: perf script -> llvm-profgen
        info "Using llvm-profgen (via perf script)..."
        perf script -i "$BOLT_DATA_DIR/perf.data" -F +ip,brstack \
            > "$BOLT_DATA_DIR/perf.script"
        llvm-profgen \
            --perfscript="$BOLT_DATA_DIR/perf.script" \
            --binary="$binary" \
            --output="$BOLT_DATA_DIR/perf.fdata"
    else
        err "Neither perf2bolt nor llvm-profgen found."
        err "Install LLVM with BOLT support or use the cargo-pgo Docker image."
        exit 1
    fi

    ok "BOLT fdata written to $BOLT_DATA_DIR/perf.fdata"
    info "Run 'bolt_optimize.sh apply <binary>' to optimize."
}

cmd_apply() {
    local binary="${1:?Usage: bolt_optimize.sh apply <binary>}"
    local output="${binary}.bolt"

    if ! command -v llvm-bolt &>/dev/null; then
        err "llvm-bolt not found. Install: apt install llvm-bolt"
        exit 1
    fi

    if [[ ! -f "$BOLT_DATA_DIR/perf.fdata" ]]; then
        err "No perf.fdata found in $BOLT_DATA_DIR. Run 'convert' first."
        exit 1
    fi

    info "Applying BOLT optimizations..."
    info "Input:  $binary"
    info "Output: $output"
    echo ""

    # Safe default flags that work well for most Rust binaries
    # shellcheck disable=SC2086
    llvm-bolt "$binary" \
        -o "$output" \
        -data="$BOLT_DATA_DIR/perf.fdata" \
        -reorder-blocks=ext-tsp \
        -reorder-functions=hfsort+ \
        -split-functions \
        -split-all-cold \
        -icf=1 \
        -align-blocks=64 \
        -update-debug-sections \
        $BOLT_EXTRA_FLAGS

    # Report size change
    local size_before size_after
    size_before=$(stat --format='%s' "$binary" 2>/dev/null || stat -f'%z' "$binary")
    size_after=$(stat --format='%s' "$output" 2>/dev/null || stat -f'%z' "$output")
    local pct
    pct=$(echo "scale=1; ($size_after - $size_before) * 100 / $size_before" | bc)

    ok "BOLT optimization complete!"
    echo "  Before: $(numfmt --to=iec "$size_before" 2>/dev/null || echo "$size_before bytes")"
    echo "  After:  $(numfmt --to=iec "$size_after" 2>/dev/null || echo "$size_after bytes")"
    echo "  Size delta: ${pct}%"
    echo ""
    echo "  Compare: hyperfine '$binary <args>' '$output <args>'"
}

cmd_full() {
    local binary="${1:?Usage: bolt_optimize.sh full <binary> <args...>}"
    shift

    if [[ "$(uname -s)" != "Linux" ]]; then
        err "Full BOLT pipeline requires Linux. Use pgo_build.sh for PGO-only on macOS."
        exit 1
    fi

    info "=== Full BOLT Pipeline ==="
    echo ""

    cmd_profile "$binary" "$@"
    echo ""

    cmd_convert "$binary"
    echo ""

    cmd_apply "$binary"
    echo ""

    ok "=== BOLT Pipeline Complete ==="
    echo "  A/B test: hyperfine '$binary <args>' '${binary}.bolt <args>'"
}

# Dispatch
case "${1:-help}" in
    profile) shift; cmd_profile "$@" ;;
    convert) shift; cmd_convert "$@" ;;
    apply)   shift; cmd_apply "$@" ;;
    full)    shift; cmd_full "$@" ;;
    help|*)
        echo "BOLT Post-Link Optimization for Rust Binaries"
        echo ""
        echo "Usage:"
        echo "  bolt_optimize.sh profile <binary> <args...>  # Collect branch profile"
        echo "  bolt_optimize.sh convert <binary>             # Convert to BOLT fdata"
        echo "  bolt_optimize.sh apply <binary>               # Apply BOLT"
        echo "  bolt_optimize.sh full <binary> <args...>      # Full pipeline"
        echo ""
        echo "Environment:"
        echo "  BOLT_DATA_DIR    - Data directory (default: /tmp/bolt-data-PID)"
        echo "  BOLT_EXTRA_FLAGS - Additional llvm-bolt flags"
        echo "  PERF_SAMPLE_RATE - Branch sample period (default: 100003)"
        echo ""
        echo "NOTE: Requires Linux. BOLT operates on ELF binaries."
        ;;
esac
