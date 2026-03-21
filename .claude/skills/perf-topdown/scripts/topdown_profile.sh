#!/bin/bash
# Top-Down profiling convenience script for x86-64 and AArch64.
#
# Usage:
#   ./topdown_profile.sh <preset> <command> [args...]
#
# Presets:
#   quick    - CPI + cache sanity check (5 repetitions)
#   topdown  - TMA Level 1 classification
#   branches - Branch trace recording (LBR on x86, SPE on ARM)
#   icache   - Instruction cache pressure analysis
#
# Architecture auto-detected via uname -m.

set -euo pipefail

PRESET="${1:-}"
shift || true

if [ -z "$PRESET" ] || [ $# -eq 0 ]; then
    cat << 'EOF'
Usage: topdown_profile.sh <preset> <command> [args...]

Presets:
  quick    - CPI + cache sanity check (-r 5)
  topdown  - TMA Level 1 classification
  branches - Branch trace recording (LBR on x86, SPE on ARM)
  icache   - Instruction cache pressure analysis

Examples:
  ./topdown_profile.sh quick ./target/release/tiny_hot
  ./topdown_profile.sh topdown taskset -c 2 ./target/release/tiny_hot
  ./topdown_profile.sh branches ./target/release/tiny_hot
  ./topdown_profile.sh icache ./target/release/tiny_hot

Architecture auto-detected. Requires sudo for most presets.
EOF
    exit 1
fi

if ! command -v perf &> /dev/null; then
    echo "Error: perf not found. Install with: apt-get install linux-perf"
    exit 1
fi

ARCH=$(uname -m)
echo "=== Top-Down Profile: preset=$PRESET arch=$ARCH ==="
echo "Command: $*"
echo

case "$ARCH" in
    x86_64)
        case "$PRESET" in
            quick)
                echo "[x86-64] Quick CPI & cache sanity (5 reps)"
                sudo perf stat -r 5 \
                    -e cycles,instructions,branch-misses,cache-misses,LLC-loads,icache_misses \
                    "$@" 2>&1 | tee /tmp/topdown-quick.log
                echo
                echo "=== Derived Metrics ==="
                # Extract cycles and instructions for CPI
                CYCLES=$(grep -m1 "cycles" /tmp/topdown-quick.log 2>/dev/null | awk '{print $1}' | tr -d ',.' || echo "")
                INSTR=$(grep -m1 "instructions" /tmp/topdown-quick.log 2>/dev/null | awk '{print $1}' | tr -d ',.' || echo "")
                if [ -n "$CYCLES" ] && [ -n "$INSTR" ] && [ "$INSTR" -gt 0 ] 2>/dev/null; then
                    CPI=$(awk "BEGIN {printf \"%.2f\", $CYCLES / $INSTR}")
                    echo "  CPI: $CPI"
                    if (( $(awk "BEGIN {print ($CPI > 1.0)}") )); then
                        echo "  -> CPI > 1.0: proceed to 'topdown' preset for classification"
                    fi
                fi
                ;;
            topdown)
                echo "[x86-64] TMA Level 1"
                # Try --topdown first (Intel), fall back to -M
                if sudo perf stat --topdown -a -- "$@" 2>&1 | tee /tmp/topdown-tma.log; then
                    echo
                    echo "If output shows '<not supported>', try: perf stat -M TopdownL1 -- <cmd>"
                    echo "For AMD Zen 4+: perf stat -M PipelineL1 -- <cmd>"
                else
                    echo
                    echo "[Fallback] --topdown not supported. Trying -M TopdownL1..."
                    if ! perf stat -M TopdownL1 -- "$@" 2>&1; then
                        echo "[Fallback] Trying AMD -M PipelineL1..."
                        perf stat -M PipelineL1 -- "$@" 2>&1 || echo "Error: No topdown support found. Check kernel version (need 4.8+ for Intel, 6.2+ for AMD)."
                    fi
                fi
                ;;
            branches)
                echo "[x86-64] LBR branch recording"
                # Check LBR availability
                if ! perf record -b -e cycles:u -- sleep 0.01 2>/dev/null; then
                    echo "Error: LBR not available (common in VMs/cloud). Use BOLT instrumentation instead."
                    exit 1
                fi
                echo "Recording branches with LBR..."
                sudo perf record -o /tmp/perf-lbr.data -c 100000 -b -e cycles:u -- "$@"
                echo
                echo "=== Top misprediction sites ==="
                perf report -i /tmp/perf-lbr.data --sort symbol_from,symbol_to,mispredict --stdio --percent-limit=1.0 2>&1 | head -40
                echo
                echo "Branch data saved to /tmp/perf-lbr.data"
                echo "Further analysis:"
                echo "  perf script -i /tmp/perf-lbr.data -F ip,sym,brstack | rustfilt | head -100"
                echo "  perf report -i /tmp/perf-lbr.data --branch-history"
                ;;
            icache)
                echo "[x86-64] Instruction cache pressure"
                sudo perf stat -r 3 \
                    -e icache_64b.iftag_miss,instructions,cycles \
                    "$@" 2>&1
                echo
                echo "High icache misses -> consider: codegen-units=1, #[inline(never)] for cold, BOLT"
                ;;
            *)
                echo "Error: Unknown preset '$PRESET'"
                exit 1
                ;;
        esac
        ;;

    aarch64)
        case "$PRESET" in
            quick)
                echo "[AArch64] Quick CPI & cache sanity (5 reps)"
                sudo perf stat -r 5 \
                    -e cpu_cycles,inst_retired,br_mis_pred_retired,l1d_cache_refill,l2d_cache_refill,l1i_cache_refill \
                    "$@" 2>&1 | tee /tmp/topdown-quick.log
                echo
                echo "=== Derived Metrics ==="
                CYCLES=$(grep -m1 "cpu_cycles" /tmp/topdown-quick.log 2>/dev/null | awk '{print $1}' | tr -d ',.' || echo "")
                INSTR=$(grep -m1 "inst_retired" /tmp/topdown-quick.log 2>/dev/null | awk '{print $1}' | tr -d ',.' || echo "")
                if [ -n "$CYCLES" ] && [ -n "$INSTR" ] && [ "$INSTR" -gt 0 ] 2>/dev/null; then
                    CPI=$(awk "BEGIN {printf \"%.2f\", $CYCLES / $INSTR}")
                    echo "  CPI: $CPI"
                    if (( $(awk "BEGIN {print ($CPI > 1.0)}") )); then
                        echo "  -> CPI > 1.0: proceed to 'topdown' preset for classification"
                    fi
                fi
                ;;
            topdown)
                echo "[AArch64] Manual topdown analysis"
                echo "Collecting topdown events..."
                sudo perf stat -r 3 \
                    -e cpu_cycles,inst_retired,stall_frontend,stall_backend,stall_backend_mem,br_mis_pred_retired \
                    "$@" 2>&1 | tee /tmp/topdown-arm.log
                echo
                echo "=== Topdown Decomposition ==="
                echo "Compute manually:"
                echo "  Frontend Bound % = stall_frontend / cpu_cycles * 100"
                echo "  Backend Bound %  = stall_backend / cpu_cycles * 100"
                echo "  Backend Memory % = stall_backend_mem / cpu_cycles * 100"
                echo "  IPC              = inst_retired / cpu_cycles"
                echo
                echo "For N2/V2+ (slot-based topdown), also try:"
                echo "  perf stat -M frontend_bound,backend_bound,bad_speculation,retiring -- <cmd>"
                ;;
            branches)
                echo "[AArch64] SPE branch recording"
                # Check SPE availability
                if [ ! -d /sys/bus/event_source/devices/arm_spe_0 ]; then
                    echo "SPE not available. Falling back to br_mis_pred_retired sampling..."
                    sudo perf record -e br_mis_pred_retired -c 1000 -g --call-graph dwarf -o /tmp/perf-branch.data -- "$@"
                    echo
                    perf report -i /tmp/perf-branch.data --stdio --percent-limit=1.0 2>&1 | head -40
                else
                    echo "Recording branch mispredictions with SPE..."
                    sudo perf record -e arm_spe/branch_filter=1,event_filter=0x80/ -o /tmp/perf-spe.data -- "$@"
                    echo
                    echo "=== Branch misprediction hotspots ==="
                    perf report -i /tmp/perf-spe.data --stdio --percent-limit=1.0 2>&1 | head -40
                    echo
                    echo "SPE data saved to /tmp/perf-spe.data"
                    echo "Further analysis: perf report -i /tmp/perf-spe.data --mem-mode"
                fi
                ;;
            icache)
                echo "[AArch64] Instruction cache pressure"
                sudo perf stat -r 3 \
                    -e l1i_cache,l1i_cache_refill,inst_retired,cpu_cycles,itlb_walk \
                    "$@" 2>&1
                echo
                echo "Compute: L1i miss rate = l1i_cache_refill / l1i_cache * 100"
                echo "High misses -> consider: codegen-units=1, #[inline(never)] for cold, BOLT"
                ;;
            *)
                echo "Error: Unknown preset '$PRESET'"
                exit 1
                ;;
        esac
        ;;

    *)
        echo "Error: Unsupported architecture '$ARCH'. Supported: x86_64, aarch64"
        exit 1
        ;;
esac

echo
echo "Full output saved. Related skills: /perf-topdown, /linux-perf-profile, /asm-forge"
