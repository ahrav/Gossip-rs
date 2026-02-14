#!/usr/bin/env bash
# collect_asm.sh — Cross-platform ASM collection for asm-forge
#
# Usage:
#   collect_asm.sh <package> <function_pattern> [output_dir]
#
# Examples:
#   collect_asm.sh scanner-rs 'rule_repr::RuleCompiled'
#   collect_asm.sh scanner-rs 'engine::core::Engine::scan' /tmp/forge
#
# Requires: cargo-show-asm (cargo install cargo-show-asm)
#
# Outputs:
#   <output_dir>/<sanitized_function_name>.s      — raw ASM
#   <output_dir>/<sanitized_function_name>.rs.s    — ASM interleaved with Rust source
#   <output_dir>/<sanitized_function_name>.ll      — LLVM-IR (optional, if --llvm flag works)

set -euo pipefail

PACKAGE="${1:?Usage: collect_asm.sh <package> <function_pattern> [output_dir]}"
PATTERN="${2:?Usage: collect_asm.sh <package> <function_pattern> [output_dir]}"
OUTDIR="${3:-/tmp/asm-forge}"

mkdir -p "$OUTDIR"

# Detect ISA
ARCH=$(uname -m)
case "$ARCH" in
    arm64|aarch64) ISA="aarch64" ;;
    x86_64)        ISA="x86-64" ;;
    *)             ISA="unknown" ;;
esac

echo "=== ASM Forge: Collecting assembly ==="
echo "Package:  $PACKAGE"
echo "Pattern:  $PATTERN"
echo "ISA:      $ISA ($ARCH)"
echo "Output:   $OUTDIR"
echo ""

# Check cargo-show-asm is installed
if ! command -v cargo-asm &>/dev/null; then
    echo "ERROR: cargo-show-asm not found. Install with: cargo install cargo-show-asm"
    exit 1
fi

# List matching functions
echo "--- Matching functions ---"
RAW_MATCHES=$(cargo asm --lib -p "$PACKAGE" 2>&1 | grep -i "$PATTERN" || true)

if [ -z "$RAW_MATCHES" ]; then
    echo "No functions matching '$PATTERN' found."
    echo ""
    echo "Try a broader search:"
    echo "  cargo asm --lib -p $PACKAGE 2>&1 | grep -i '<keyword>'"
    exit 1
fi

echo "$RAW_MATCHES"
echo ""

# Extract just the function name from cargo asm listing format:
#   1569 "scanner_rs::engine::rule_repr::PackedPatternsBuilder::build" [229]
# We need just the part inside the quotes.
MATCHES=$(echo "$RAW_MATCHES" | sed -n 's/.*"\(.*\)".*/\1/p')

if [ -z "$MATCHES" ]; then
    # Fallback: maybe the pattern matched a non-quoted format
    MATCHES="$RAW_MATCHES"
fi

# Collect ASM for each matching function
echo "$MATCHES" | while IFS= read -r func; do
    # Sanitize function name for filename
    SAFE_NAME=$(echo "$func" | sed 's/[<>: ]/_/g' | sed 's/__*/_/g' | sed 's/^_//' | head -c 200)

    echo "--- Collecting: $func ---"

    # Raw ASM
    echo "  ASM → $OUTDIR/${SAFE_NAME}.s"
    cargo asm --lib -p "$PACKAGE" "$func" > "$OUTDIR/${SAFE_NAME}.s" 2>/dev/null || {
        echo "  WARN: Failed to collect ASM for $func (may be ambiguous)"
        continue
    }

    # ASM interleaved with Rust source
    echo "  ASM+Rust → $OUTDIR/${SAFE_NAME}.rs.s"
    cargo asm --lib -p "$PACKAGE" --rust "$func" > "$OUTDIR/${SAFE_NAME}.rs.s" 2>/dev/null || {
        echo "  WARN: Failed to collect interleaved ASM"
    }

    # LLVM-IR
    echo "  LLVM-IR → $OUTDIR/${SAFE_NAME}.ll"
    cargo asm --lib -p "$PACKAGE" --llvm "$func" > "$OUTDIR/${SAFE_NAME}.ll" 2>/dev/null || {
        echo "  WARN: Failed to collect LLVM-IR"
    }

    # Stats
    if [ -f "$OUTDIR/${SAFE_NAME}.s" ]; then
        LINES=$(wc -l < "$OUTDIR/${SAFE_NAME}.s" | tr -d ' ')
        echo "  Instructions: ~$LINES lines"

        # Count potential issues
        ASM_FILE="$OUTDIR/${SAFE_NAME}.s"
        count_pat() { grep -c "$1" "$ASM_FILE" 2>/dev/null | tr -d '[:space:]' || printf '0'; }

        case "$ISA" in
            x86-64)
                PANICS=$(count_pat 'panic\|slice_index')
                SPILLS=$(count_pat '\[rsp')
                BRANCHES=$(count_pat 'j[a-z]')
                CALLS=$(count_pat 'call')
                SIMD=$(count_pat 'ymm\|xmm\|zmm')
                ;;
            aarch64)
                PANICS=$(count_pat 'panic\|slice_index')
                SPILLS=$(count_pat '\[sp,')
                BRANCHES=$(count_pat 'b\.\|cbz\|cbnz\|tbz\|tbnz')
                CALLS=$(count_pat '	bl	\|	bl ')
                SIMD=$(count_pat '\.16b\|\.8h\|\.4s\|\.2d')
                ;;
            *)
                PANICS=0; SPILLS=0; BRANCHES=0; CALLS=0; SIMD=0
                ;;
        esac

        echo "  Quick stats: panics=$PANICS spills=$SPILLS branches=$BRANCHES calls=$CALLS simd=$SIMD"
    fi

    echo ""
done

echo "=== Collection complete: $OUTDIR ==="
echo ""
echo "Next steps:"
echo "  1. Read the .rs.s files (interleaved ASM + Rust source)"
echo "  2. Audit for red flags (see references/asm-red-flags.md)"
echo "  3. Apply forge techniques (see references/forge-techniques.md)"
