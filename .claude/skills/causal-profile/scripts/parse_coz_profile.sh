#!/bin/bash
# Parse a coz profile.coz file and produce a human-readable summary.
#
# Usage:
#   ./parse_coz_profile.sh <profile.coz>
#
# Output:
#   - Experiment count and runtime summary
#   - Progress point activity
#   - Per-line speedup curves (sorted by impact)
#   - Contention detection (negative slopes)

set -euo pipefail

PROFILE="${1:-}"

if [ -z "$PROFILE" ] || [ ! -f "$PROFILE" ]; then
    echo "Usage: parse_coz_profile.sh <profile.coz>"
    echo ""
    echo "Parses a coz profile and produces a ranked summary of optimization targets."
    exit 1
fi

echo "=== Causal Profile Analysis ==="
echo "File: $PROFILE"
echo ""

# Basic counts
EXPERIMENTS=$(grep -c '^experiment' "$PROFILE" 2>/dev/null || echo "0")
STARTUPS=$(grep -c '^startup' "$PROFILE" 2>/dev/null || echo "0")
RUNTIMES=$(grep -c '^runtime' "$PROFILE" 2>/dev/null || echo "0")
THROUGHPUT_POINTS=$(grep -c '^throughput-point' "$PROFILE" 2>/dev/null || echo "0")
LATENCY_POINTS=$(grep -c '^latency-point' "$PROFILE" 2>/dev/null || echo "0")

echo "--- Summary ---"
echo "  Experiments:       $EXPERIMENTS"
echo "  Startup records:   $STARTUPS"
echo "  Runtime records:   $RUNTIMES"
echo "  Throughput points: $THROUGHPUT_POINTS"
echo "  Latency points:    $LATENCY_POINTS"
echo ""

if [ "$EXPERIMENTS" -eq 0 ]; then
    echo "*** WARNING: Zero experiments recorded ***"
    echo ""
    echo "Possible causes:"
    echo "  1. coz crate v0.1.3 bug (missing _coz_add_delays) — use git master"
    echo "  2. Missing debug info — build with debug = 1 or debug = 2"
    echo "  3. Progress point never reached — verify instrumentation"
    echo "  4. Runtime too short — run for at least 30 seconds"
    echo ""
    echo "Run the pre-flight check script to diagnose."
    exit 1
fi

# Extract unique lines that were experimented on
echo "--- Lines Profiled ---"
grep '^experiment' "$PROFILE" \
    | sed 's/.*selected=\([^ \t]*\).*/\1/' \
    | sort | uniq -c | sort -rn \
    | head -20 \
    | while read -r count line; do
        printf "  %4d experiments  %s\n" "$count" "$line"
    done
echo ""

# Extract unique speedup levels used
echo "--- Speedup Levels ---"
grep '^experiment' "$PROFILE" \
    | sed 's/.*speedup=\([^ \t]*\).*/\1/' \
    | sort -n | uniq -c \
    | while read -r count level; do
        printf "  %4d experiments at speedup=%s\n" "$count" "$level"
    done
echo ""

# Extract progress point data
echo "--- Progress Points ---"
if [ "$THROUGHPUT_POINTS" -gt 0 ]; then
    echo "  Throughput points:"
    grep '^throughput-point' "$PROFILE" \
        | sed 's/.*name=\([^ \t]*\)\tδ=\([^ \t]*\)/    \1  delta=\2/' \
        | head -10
fi
if [ "$LATENCY_POINTS" -gt 0 ]; then
    echo "  Latency points:"
    grep '^latency-point' "$PROFILE" \
        | head -10 \
        | sed 's/^/    /'
fi
echo ""

# Compute per-line impact estimates using awk.
# For each (line, speedup_level), compute the average program effect.
# Then estimate slope as the linear regression coefficient.
echo "--- Optimization Targets (ranked by estimated impact) ---"
echo ""
echo "  Positive slopes = worth optimizing"
echo "  Negative slopes = contention (fix synchronization, not speed)"
echo "  Near-zero slopes = not on critical path (skip)"
echo ""

grep '^experiment' "$PROFILE" \
    | awk -F'\t' '
    {
        # Parse fields from tab-separated experiment line
        selected = ""
        speedup = ""
        duration = ""
        delta = ""
        samples = ""
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^selected=/) { split($i, a, "="); selected = a[2] }
            if ($i ~ /^speedup=/) { split($i, a, "="); speedup = a[2] + 0 }
            if ($i ~ /^duration=/) { split($i, a, "="); duration = a[2] + 0 }
            if ($i ~ /^selected-samples=/) { split($i, a, "="); samples = a[2] + 0 }
        }
        if (selected == "" || duration == 0) next

        # Accumulate for linear regression
        n[selected]++
        sum_x[selected] += speedup
        sum_y[selected] += duration
        sum_xy[selected] += speedup * duration
        sum_xx[selected] += speedup * speedup

        # Track baseline (speedup=0) duration
        if (speedup == 0) {
            baseline_count[selected]++
            baseline_sum[selected] += duration
        }
    }
    END {
        # Compute slope for each line
        for (line in n) {
            if (n[line] < 3) continue  # need minimum data points
            nn = n[line]
            denom = nn * sum_xx[line] - sum_x[line] * sum_x[line]
            if (denom == 0) continue
            slope = (nn * sum_xy[line] - sum_x[line] * sum_y[line]) / denom

            # Normalize slope relative to baseline duration
            if (baseline_count[line] > 0) {
                baseline_avg = baseline_sum[line] / baseline_count[line]
                if (baseline_avg > 0) {
                    # Positive normalized slope = speeding up this line speeds up program
                    # (duration decreases as speedup increases, so slope is negative in raw terms)
                    normalized = -(slope / baseline_avg)
                } else {
                    normalized = 0
                }
            } else {
                normalized = 0
            }

            printf "%+.4f\t%d\t%s\n", normalized, nn, line
        }
    }' \
    | sort -t$'\t' -k1 -rn \
    | head -30 \
    | awk -F'\t' '
    BEGIN {
        rank = 0
        printf "  %-4s  %-8s  %-6s  %s\n", "Rank", "Impact", "Expts", "Source Line"
        printf "  %-4s  %-8s  %-6s  %s\n", "----", "------", "-----", "-----------"
    }
    {
        rank++
        impact = $1 + 0
        expts = $2
        line = $3

        if (impact > 0.05) {
            category = "OPTIMIZE"
        } else if (impact < -0.05) {
            category = "CONTENTION"
        } else {
            category = "skip"
        }

        printf "  %-4d  %+.4f  %-6d  %s  [%s]\n", rank, impact, expts, line, category
    }'

echo ""
echo "=== End of Analysis ==="
