#!/usr/bin/env bash
# A/B verification script for PGO and BOLT optimized binaries.
# Compares baseline, PGO-only, and PGO+BOLT builds with hyperfine.
#
# Usage:
#   verify_improvement.sh <binary> <args...>
#
# Expects these binary variants to exist:
#   <binary>           - The current (optimized) build
#   <binary>.baseline  - The original unoptimized build
#   <binary>.bolt      - The BOLT-optimized build (optional)
#
# Or use explicit paths:
#   verify_improvement.sh --baseline <path1> --pgo <path2> [--bolt <path3>] -- <args...>

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[verify]${NC} $*"; }
ok()    { echo -e "${GREEN}[verify]${NC} $*"; }
warn()  { echo -e "${YELLOW}[verify]${NC} $*"; }
err()   { echo -e "${RED}[verify]${NC} $*" >&2; }

WARMUP="${WARMUP:-3}"
MIN_RUNS="${MIN_RUNS:-10}"
EXPORT_JSON="${EXPORT_JSON:-}"

usage() {
    echo "PGO/BOLT Verification — A/B Benchmark Comparison"
    echo ""
    echo "Usage:"
    echo "  verify_improvement.sh <binary> <args...>"
    echo "    Looks for <binary>.baseline and <binary>.bolt automatically"
    echo ""
    echo "  verify_improvement.sh --baseline <p1> --pgo <p2> [--bolt <p3>] -- <args>"
    echo "    Explicit binary paths"
    echo ""
    echo "Environment:"
    echo "  WARMUP    - Warmup runs (default: 3)"
    echo "  MIN_RUNS  - Minimum benchmark runs (default: 10)"
    echo "  EXPORT_JSON - Path to export JSON results (optional)"
}

# Simple mode: infer paths from binary name
simple_mode() {
    local binary="$1"
    shift
    local args=("$@")

    local baseline="${binary}.baseline"
    local pgo_bin="$binary"
    local bolt_bin="${binary}.bolt"

    # Check what's available
    local have_baseline=false have_bolt=false
    [[ -x "$baseline" ]] && have_baseline=true
    [[ -x "$bolt_bin" ]] && have_bolt=true

    if ! $have_baseline; then
        err "Baseline not found at $baseline"
        err "Save the unoptimized binary first: cp $binary ${binary}.baseline"
        exit 1
    fi

    info "=== PGO/BOLT Verification ==="
    echo ""
    info "Baseline: $baseline"
    info "PGO:      $pgo_bin"
    if $have_bolt; then
        info "BOLT:     $bolt_bin"
    else
        info "BOLT:     (not available)"
    fi
    info "Args:     ${args[*]:-<none>}"
    info "Warmup:   $WARMUP | Min runs: $MIN_RUNS"
    echo ""

    # Step 1: Correctness check
    info "--- Correctness Check ---"
    local baseline_out pgo_out
    baseline_out=$("$baseline" "${args[@]}" 2>&1 || true)
    pgo_out=$("$pgo_bin" "${args[@]}" 2>&1 || true)

    if [[ "$baseline_out" == "$pgo_out" ]]; then
        ok "PGO output matches baseline"
    else
        warn "PGO output differs from baseline — verify this is expected"
        echo "  First difference:"
        diff <(echo "$baseline_out") <(echo "$pgo_out") | head -5 || true
    fi

    if $have_bolt; then
        local bolt_out
        bolt_out=$("$bolt_bin" "${args[@]}" 2>&1 || true)
        if [[ "$baseline_out" == "$bolt_out" ]]; then
            ok "BOLT output matches baseline"
        else
            warn "BOLT output differs from baseline — verify this is expected"
        fi
    fi
    echo ""

    # Step 2: Performance comparison
    info "--- Performance Comparison ---"

    local hyperfine_args=(
        --warmup "$WARMUP"
        --min-runs "$MIN_RUNS"
        --style full
    )

    if [[ -n "$EXPORT_JSON" ]]; then
        hyperfine_args+=(--export-json "$EXPORT_JSON")
    fi

    # Escape arguments for safe interpolation into hyperfine command strings.
    # Without escaping, arguments containing spaces or shell metacharacters
    # would break when hyperfine passes them to its internal shell.
    local escaped_args=""
    if [[ ${#args[@]} -gt 0 ]]; then
        escaped_args=" $(printf '%q ' "${args[@]}")"
    fi

    # Escape binary paths for the same reason — paths with spaces or special
    # characters would break hyperfine's internal shell invocation.
    local escaped_baseline escaped_pgo escaped_bolt
    escaped_baseline=$(printf '%q' "$baseline")
    escaped_pgo=$(printf '%q' "$pgo_bin")
    escaped_bolt=$(printf '%q' "$bolt_bin")

    if $have_bolt; then
        # 3-way comparison
        hyperfine "${hyperfine_args[@]}" \
            -n 'baseline'  "${escaped_baseline}${escaped_args}" \
            -n 'pgo-only'  "${escaped_pgo}${escaped_args}" \
            -n 'pgo+bolt'  "${escaped_bolt}${escaped_args}"
    else
        # 2-way comparison
        hyperfine "${hyperfine_args[@]}" \
            -n 'baseline' "${escaped_baseline}${escaped_args}" \
            -n 'pgo-only' "${escaped_pgo}${escaped_args}"
    fi

    echo ""
    ok "=== Verification Complete ==="
}

# Explicit mode: user specifies paths
explicit_mode() {
    local baseline="" pgo="" bolt="" args=()
    local parsing_args=false

    while [[ $# -gt 0 ]]; do
        if $parsing_args; then
            args+=("$1")
            shift
            continue
        fi
        case "$1" in
            --baseline) baseline="$2"; shift 2 ;;
            --pgo)      pgo="$2"; shift 2 ;;
            --bolt)     bolt="$2"; shift 2 ;;
            --)         parsing_args=true; shift ;;
            *)          err "Unknown flag: $1"; usage; exit 1 ;;
        esac
    done

    if [[ -z "$baseline" || -z "$pgo" ]]; then
        err "Must specify at least --baseline and --pgo"
        usage
        exit 1
    fi

    info "=== PGO/BOLT Verification ==="
    echo ""

    local hyperfine_args=(
        --warmup "$WARMUP"
        --min-runs "$MIN_RUNS"
        --style full
    )

    if [[ -n "$EXPORT_JSON" ]]; then
        hyperfine_args+=(--export-json "$EXPORT_JSON")
    fi

    local escaped_args=""
    if [[ ${#args[@]} -gt 0 ]]; then
        escaped_args=" $(printf '%q ' "${args[@]}")"
    fi

    local escaped_baseline escaped_pgo escaped_bolt
    escaped_baseline=$(printf '%q' "$baseline")
    escaped_pgo=$(printf '%q' "$pgo")
    [[ -n "$bolt" ]] && escaped_bolt=$(printf '%q' "$bolt")

    if [[ -n "$bolt" ]]; then
        hyperfine "${hyperfine_args[@]}" \
            -n 'baseline' "${escaped_baseline}${escaped_args}" \
            -n 'pgo-only' "${escaped_pgo}${escaped_args}" \
            -n 'pgo+bolt' "${escaped_bolt}${escaped_args}"
    else
        hyperfine "${hyperfine_args[@]}" \
            -n 'baseline' "${escaped_baseline}${escaped_args}" \
            -n 'pgo-only' "${escaped_pgo}${escaped_args}"
    fi

    echo ""
    ok "=== Verification Complete ==="
}

# Main dispatch
if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi

case "$1" in
    --baseline|--pgo|--bolt)
        explicit_mode "$@"
        ;;
    --help|-h|help)
        usage
        ;;
    *)
        simple_mode "$@"
        ;;
esac
