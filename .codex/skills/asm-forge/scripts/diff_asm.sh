#!/usr/bin/env bash
# diff_asm.sh — Compare ASM before and after an optimization
#
# Usage:
#   diff_asm.sh <before.s> <after.s>
#
# Outputs a summary of changes and the full diff.
#
# Example:
#   diff_asm.sh /tmp/asm-forge/before/fn.s /tmp/asm-forge/after/fn.s

set -euo pipefail

BEFORE="${1:?Usage: diff_asm.sh <before.s> <after.s>}"
AFTER="${2:?Usage: diff_asm.sh <before.s> <after.s>}"

if [ ! -f "$BEFORE" ]; then
    echo "ERROR: Before file not found: $BEFORE"
    exit 1
fi

if [ ! -f "$AFTER" ]; then
    echo "ERROR: After file not found: $AFTER"
    exit 1
fi

# Detect ISA from file contents
if grep -q 'rsp\|rax\|rdi' "$BEFORE" 2>/dev/null; then
    ISA="x86-64"
elif grep -q '\[sp,\|x[0-9]\+,' "$BEFORE" 2>/dev/null; then
    ISA="aarch64"
else
    ISA="unknown"
fi

echo "=== ASM Forge: Diff Report ==="
echo "ISA:    $ISA"
echo "Before: $BEFORE"
echo "After:  $AFTER"
echo ""

# Line counts
LINES_BEFORE=$(wc -l < "$BEFORE" | tr -d ' ')
LINES_AFTER=$(wc -l < "$AFTER" | tr -d ' ')
DELTA=$((LINES_AFTER - LINES_BEFORE))

echo "--- Instruction Count ---"
echo "Before: $LINES_BEFORE lines"
echo "After:  $LINES_AFTER lines"
if [ "$DELTA" -lt 0 ]; then
    echo "Delta:  $DELTA lines (SMALLER — good)"
elif [ "$DELTA" -gt 0 ]; then
    echo "Delta:  +$DELTA lines (LARGER — investigate)"
else
    echo "Delta:  0 lines (same size)"
fi
echo ""

# Pattern-specific metrics
echo "--- Pattern Analysis ---"

count_pattern() {
    local file="$1"
    local pattern="$2"
    local n
    n=$(grep -c "$pattern" "$file" 2>/dev/null || true)
    n="${n//[^0-9]/}"  # strip any non-digit chars (whitespace/newlines)
    printf '%s' "${n:-0}"
}

case "$ISA" in
    x86-64)
        echo "| Metric | Before | After | Delta |"
        echo "|--------|--------|-------|-------|"

        B=$(count_pattern "$BEFORE" 'panic\|slice_index')
        A=$(count_pattern "$AFTER" 'panic\|slice_index')
        echo "| Panic paths | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" '\[rsp')
        A=$(count_pattern "$AFTER" '\[rsp')
        echo "| Stack accesses | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" 'j[a-z]*\s')
        A=$(count_pattern "$AFTER" 'j[a-z]*\s')
        echo "| Branches | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" 'call\s')
        A=$(count_pattern "$AFTER" 'call\s')
        echo "| Function calls | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" 'cmov')
        A=$(count_pattern "$AFTER" 'cmov')
        echo "| Cmov (branchless) | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" 'ymm\|xmm\|zmm')
        A=$(count_pattern "$AFTER" 'ymm\|xmm\|zmm')
        echo "| SIMD instructions | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" 'div\b')
        A=$(count_pattern "$AFTER" 'div\b')
        echo "| Division | $B | $A | $((A - B)) |"
        ;;

    aarch64)
        echo "| Metric | Before | After | Delta |"
        echo "|--------|--------|-------|-------|"

        B=$(count_pattern "$BEFORE" 'panic\|slice_index')
        A=$(count_pattern "$AFTER" 'panic\|slice_index')
        echo "| Panic paths | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" '\[sp,')
        A=$(count_pattern "$AFTER" '\[sp,')
        echo "| Stack accesses | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" 'b\.\|cbz\|cbnz\|tbz\|tbnz')
        A=$(count_pattern "$AFTER" 'b\.\|cbz\|cbnz\|tbz\|tbnz')
        echo "| Branches | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" 'bl\s')
        A=$(count_pattern "$AFTER" 'bl\s')
        echo "| Function calls | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" 'csel\|csinc\|csneg\|csinv')
        A=$(count_pattern "$AFTER" 'csel\|csinc\|csneg\|csinv')
        echo "| Csel (branchless) | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" '\.16b\|\.8h\|\.4s\|\.2d')
        A=$(count_pattern "$AFTER" '\.16b\|\.8h\|\.4s\|\.2d')
        echo "| NEON instructions | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" 'udiv\|sdiv')
        A=$(count_pattern "$AFTER" 'udiv\|sdiv')
        echo "| Division | $B | $A | $((A - B)) |"

        B=$(count_pattern "$BEFORE" 'madd\|msub')
        A=$(count_pattern "$AFTER" 'madd\|msub')
        echo "| Fused mul-add | $B | $A | $((A - B)) |"
        ;;

    *)
        echo "(ISA not detected — skipping pattern analysis)"
        ;;
esac

echo ""

# Full diff
echo "--- Full Diff ---"
echo "(Lines starting with - are removed, + are added)"
echo ""
diff -u "$BEFORE" "$AFTER" || true

echo ""
echo "=== Diff complete ==="
echo ""
echo "Verdict checklist:"
echo "  [ ] Panic paths decreased or stayed same?"
echo "  [ ] Stack accesses (spills) decreased?"
echo "  [ ] Branch count decreased or replaced with cmov/csel?"
echo "  [ ] SIMD instructions increased (if targeting vectorization)?"
echo "  [ ] Total instruction count decreased?"
echo "  [ ] Now run benchmarks to confirm wall-clock improvement"
