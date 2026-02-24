#!/usr/bin/env bash
# check_autovec.sh - Check whether rustc auto-vectorized a function.
#
# Usage: check_autovec.sh <crate> <function_path>
#
# Requires: cargo-show-asm (install with: cargo install cargo-show-asm)
# Examines assembly output for SIMD instructions and reports a JSON summary.
# Compatible with Bash 3.2+ (no associative arrays).

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() { printf 'error: %s\n' "$1" >&2; exit 1; }

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") <crate> <function_path>

Arguments:
  crate           Crate name (as it appears in Cargo.toml)
  function_path   Fully-qualified function path (e.g. mycrate::simd::process)

Example:
  $(basename "$0") scanner-rs scanner_rs::engine::core::process_batch
EOF
    exit 1
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found in PATH"
}

require_tool jq

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

[[ $# -ge 2 ]] || usage

crate="$1"
func_path="$2"

# ---------------------------------------------------------------------------
# Tool checks
# ---------------------------------------------------------------------------

command -v cargo >/dev/null 2>&1 || die "'cargo' is required but not found in PATH"

if ! cargo asm --help >/dev/null 2>&1; then
    die "'cargo-show-asm' is required but not installed. Install with: cargo install cargo-show-asm"
fi

# ---------------------------------------------------------------------------
# Detect architecture
# ---------------------------------------------------------------------------

raw_arch="$(uname -m)"
case "$raw_arch" in
    arm64|aarch64) arch="aarch64" ;;
    amd64|x86_64)  arch="x86_64"  ;;
    *)             arch="$raw_arch" ;;
esac

# ---------------------------------------------------------------------------
# Collect assembly
# ---------------------------------------------------------------------------

asm_output="$(cargo asm --lib -p "$crate" "$func_path" 2>&1)" || {
    die "cargo asm failed. Ensure the crate and function path are correct.
Output: $asm_output"
}

# Total instruction count (non-empty, non-comment, non-label lines)
# Assembly lines typically start with whitespace + mnemonic.
total_instructions="$(echo "$asm_output" \
    | grep -cE '^\s+[a-zA-Z]' || true)"

# ---------------------------------------------------------------------------
# Count SIMD vs scalar instructions
# ---------------------------------------------------------------------------

simd_count=0
scalar_count=0

# Track widths seen using simple flag variables (Bash 3.2 compatible)
width_128=0
width_256=0
width_512=0
width_scalable=0

if [[ "$arch" == "x86_64" ]]; then
    # ---- AVX instructions (v-prefixed: vpaddb, vmovaps, vfmadd, etc.) ----
    avx_count="$(echo "$asm_output" \
        | grep -cE '^\s+v[a-z]' || true)"

    # ---- SSE packed instructions ----
    # movdqa, movdqu, movaps, movapd, movups, movupd (packed moves)
    # padd*, psub*, pmul*, pand, por, pxor, pcmp*, pshuf* (packed integer)
    sse_packed_count="$(echo "$asm_output" \
        | grep -cE '^\s+(movdq[au]|movap[sd]|movup[sd]|padd[bwdq]|psub[bwdq]|pmul[a-z]*|pand|pandn|por|pxor|pcmp[a-z]*|pshuf[a-z]*|punpck[a-z]*|packss|packus|pmovmsk|pblend|palign|pmaddwd|psadbw|phsub|phadd)\b' || true)"

    simd_count=$(( avx_count + sse_packed_count ))

    # ---- Detect vector widths used ----
    # 512-bit: zmm registers
    if echo "$asm_output" | grep -qE 'zmm[0-9]' 2>/dev/null; then
        width_512=1
    fi
    # 256-bit: ymm registers
    if echo "$asm_output" | grep -qE 'ymm[0-9]' 2>/dev/null; then
        width_256=1
    fi
    # 128-bit: xmm registers
    if echo "$asm_output" | grep -qE 'xmm[0-9]' 2>/dev/null; then
        width_128=1
    fi

elif [[ "$arch" == "aarch64" ]]; then
    # ---- NEON vector operations ----
    # Load/store: ld1, ld2, ld3, ld4, st1, st2, st3, st4
    neon_ldst="$(echo "$asm_output" \
        | grep -cE '^\s+(ld[1-4]|st[1-4])\s' || true)"

    # Instructions with vector type qualifier (e.g., add v0.4s, sub v1.8h)
    neon_vec_ops="$(echo "$asm_output" \
        | grep -cE '^\s+[a-z]+\s+v[0-9]+\.(16b|8b|8h|4h|4s|2s|2d|1d)' || true)"

    # FMLA and other float vector ops with vector registers
    neon_fmla="$(echo "$asm_output" \
        | grep -cE '^\s+(fmla|fmls|fmul|fadd|fsub|fabs|fneg|fmax|fmin|fcmp|fcvt[a-z]*)\s+v[0-9]+' || true)"

    # Other common NEON: movi, dup, tbl, ext, zip, uzp, trn, cnt, rev, addv, etc.
    neon_misc="$(echo "$asm_output" \
        | grep -cE '^\s+(movi|dup|tbl|tbx|ext|zip[12]|uzp[12]|trn[12]|cnt|rev(16|32|64)|addv|saddl[2v]?|uaddl[2v]?|smull[2]?|umull[2]?|smlal[2]?|umlal[2]?|addp|sminv|uminv|smaxv|umaxv)\s' || true)"

    # ---- SVE instructions ----
    sve_count="$(echo "$asm_output" \
        | grep -cE '^\s+(ld1[bhwd]|st1[bhwd]|whilel[eto]|ptrue|pfalse|sel|splice|compact|rev\s+z|add\s+z|sub\s+z|mul\s+z|fmla\s+z|fadd\s+z|fsub\s+z|fmul\s+z)\b' || true)"

    simd_count=$(( neon_ldst + neon_vec_ops + neon_fmla + neon_misc + sve_count ))

    # ---- Detect vector widths used ----
    if [[ $neon_ldst -gt 0 ]] || [[ $neon_vec_ops -gt 0 ]] || [[ $neon_fmla -gt 0 ]] || [[ $neon_misc -gt 0 ]]; then
        width_128=1
    fi
    if [[ $sve_count -gt 0 ]]; then
        width_scalable=1
    fi
fi

scalar_count=$(( total_instructions - simd_count ))
if [[ $scalar_count -lt 0 ]]; then
    scalar_count=0
fi

# ---------------------------------------------------------------------------
# Determine auto-vectorization status
# ---------------------------------------------------------------------------

auto_vectorized=false
if [[ $simd_count -gt 0 ]]; then
    auto_vectorized=true
fi

# ---------------------------------------------------------------------------
# Compute SIMD ratio
# ---------------------------------------------------------------------------

simd_ratio="0.0"
if [[ $total_instructions -gt 0 ]]; then
    simd_ratio="$(awk "BEGIN {printf \"%.4f\", $simd_count / $total_instructions}")"
fi

# ---------------------------------------------------------------------------
# Build vector_widths_used array
# ---------------------------------------------------------------------------

widths_json="[]"
if [[ $width_128 -eq 1 ]]; then
    widths_json="$(echo "$widths_json" | jq '. + [128]')"
fi
if [[ $width_256 -eq 1 ]]; then
    widths_json="$(echo "$widths_json" | jq '. + [256]')"
fi
if [[ $width_512 -eq 1 ]]; then
    widths_json="$(echo "$widths_json" | jq '. + [512]')"
fi
if [[ $width_scalable -eq 1 ]]; then
    widths_json="$(echo "$widths_json" | jq '. + ["scalable"]')"
fi

# Sort for deterministic output
widths_json="$(echo "$widths_json" | jq 'sort')"

# ---------------------------------------------------------------------------
# Output JSON
# ---------------------------------------------------------------------------

jq -n \
    --arg function "$func_path" \
    --arg arch "$arch" \
    --argjson auto_vectorized "$auto_vectorized" \
    --argjson simd_instruction_count "$simd_count" \
    --argjson scalar_instruction_count "$scalar_count" \
    --argjson total_instructions "$total_instructions" \
    --argjson vector_widths_used "$widths_json" \
    --argjson simd_ratio "$simd_ratio" \
    '{
        function: $function,
        arch: $arch,
        auto_vectorized: $auto_vectorized,
        simd_instruction_count: $simd_instruction_count,
        scalar_instruction_count: $scalar_instruction_count,
        total_instructions: $total_instructions,
        vector_widths_used: $vector_widths_used,
        simd_ratio: $simd_ratio
    }'
