#!/usr/bin/env bash
# detect_simd.sh - Detect host SIMD capabilities and output structured JSON.
#
# Works on macOS (Apple Silicon + Intel) and Linux (x86_64 + aarch64).
# Compatible with Bash 3.2+ (no associative arrays).
# Requires: jq, uname. Optional: rustc.

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() { printf 'error: %s\n' "$1" >&2; exit 1; }

require_tool() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found in PATH"
}

require_tool jq

# ---------------------------------------------------------------------------
# Architecture & OS
# ---------------------------------------------------------------------------

raw_arch="$(uname -m)"
case "$raw_arch" in
    arm64)   arch="aarch64" ;;
    amd64)   arch="x86_64"  ;;
    x86_64)  arch="x86_64"  ;;
    aarch64) arch="aarch64" ;;
    *)       arch="$raw_arch" ;;
esac

raw_os="$(uname -s)"
case "$raw_os" in
    Darwin) os="darwin" ;;
    Linux)  os="linux"  ;;
    *)      os="$(echo "$raw_os" | tr '[:upper:]' '[:lower:]')" ;;
esac

# ---------------------------------------------------------------------------
# Rust target triple
# ---------------------------------------------------------------------------

rust_target=""
if command -v rustc >/dev/null 2>&1; then
    rust_target="$(rustc -vV 2>/dev/null | awk '/^host:/{print $2}')"
fi

# ---------------------------------------------------------------------------
# CPU model
# ---------------------------------------------------------------------------

cpu_model="unknown"
if [[ "$os" == "darwin" ]]; then
    cpu_model="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
    if [[ -z "$cpu_model" ]]; then
        # Apple Silicon: try system_profiler
        cpu_model="$(system_profiler SPHardwareDataType 2>/dev/null \
                     | awk -F': ' '/Chip/{print $2}' | head -1 || true)"
    fi
    cpu_model="${cpu_model:-Apple Silicon}"
elif [[ "$os" == "linux" ]]; then
    cpu_model="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null \
                 | sed 's/.*: //' || true)"
    if [[ -z "$cpu_model" ]]; then
        cpu_model="$(lscpu 2>/dev/null | awk -F': +' '/Model name/{print $2}' || true)"
    fi
    cpu_model="${cpu_model:-unknown}"
fi

# ---------------------------------------------------------------------------
# Feature detection — build features JSON object with jq
# ---------------------------------------------------------------------------

# Start with an empty JSON object; we accumulate features into it.
features_json="{}"

# Helper: set a feature to true or false in features_json.
set_feature() {
    local name="$1" val="$2"
    features_json="$(echo "$features_json" | jq --arg k "$name" --argjson v "$val" '. + {($k): $v}')"
}

# Helper: get a feature value (returns "true" or "false" string).
get_feature() {
    echo "$features_json" | jq -r --arg k "$1" '.[$k] // "false"'
}

# --- Rust cfg features (works on any platform) ----------------------------
rustc_cfg_features=""
if command -v rustc >/dev/null 2>&1; then
    rustc_cfg_features="$(rustc --print cfg 2>/dev/null || true)"
fi

has_rustc_feature() {
    echo "$rustc_cfg_features" | grep -q "target_feature=\"$1\"" 2>/dev/null
}

# --- x86_64 features -----------------------------------------------------
if [[ "$arch" == "x86_64" ]]; then
    # Initialize all features to false
    for feat in sse2 ssse3 sse4.1 sse4.2 avx avx2 avx512f avx512bw avx512vl avx512vbmi bmi1 bmi2 popcnt fma; do
        set_feature "$feat" false
    done

    # 1) rustc --print cfg (most reliable for what the compiler will use)
    for feat in sse2 ssse3 sse4.1 sse4.2 avx avx2 avx512f avx512bw avx512vl avx512vbmi bmi1 bmi2 popcnt fma; do
        if has_rustc_feature "$feat"; then
            set_feature "$feat" true
        fi
    done

    # 2) Platform-specific supplemental checks
    if [[ "$os" == "darwin" ]]; then
        cpu_feat_line="$(sysctl -n machdep.cpu.features 2>/dev/null || true)"
        cpu_leaf7="$(sysctl -n machdep.cpu.leaf7_features 2>/dev/null || true)"
        all_cpu_flags="$cpu_feat_line $cpu_leaf7"

        check_flag() {
            echo "$all_cpu_flags" | tr ' ' '\n' | grep -qi "^${1}$" 2>/dev/null
        }

        check_flag SSE2      && set_feature "sse2" true
        check_flag SSSE3     && set_feature "ssse3" true
        check_flag SSE4.1    && set_feature "sse4.1" true
        check_flag SSE4.2    && set_feature "sse4.2" true
        check_flag AVX1.0    && set_feature "avx" true
        check_flag AVX2.0    && set_feature "avx2" true
        check_flag AVX512F   && set_feature "avx512f" true
        check_flag AVX512BW  && set_feature "avx512bw" true
        check_flag AVX512VL  && set_feature "avx512vl" true
        check_flag AVX512VBMI && set_feature "avx512vbmi" true
        check_flag BMI1      && set_feature "bmi1" true
        check_flag BMI2      && set_feature "bmi2" true
        check_flag POPCNT    && set_feature "popcnt" true
        check_flag FMA       && set_feature "fma" true

    elif [[ "$os" == "linux" ]]; then
        cpu_flags="$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | sed 's/.*: //' || true)"

        check_linux_flag() {
            echo " $cpu_flags " | grep -q " $1 " 2>/dev/null
        }

        check_linux_flag sse2       && set_feature "sse2" true
        check_linux_flag ssse3      && set_feature "ssse3" true
        check_linux_flag sse4_1     && set_feature "sse4.1" true
        check_linux_flag sse4_2     && set_feature "sse4.2" true
        check_linux_flag avx        && set_feature "avx" true
        check_linux_flag avx2       && set_feature "avx2" true
        check_linux_flag avx512f    && set_feature "avx512f" true
        check_linux_flag avx512bw   && set_feature "avx512bw" true
        check_linux_flag avx512vl   && set_feature "avx512vl" true
        check_linux_flag avx512vbmi && set_feature "avx512vbmi" true
        check_linux_flag bmi1       && set_feature "bmi1" true
        check_linux_flag bmi2       && set_feature "bmi2" true
        check_linux_flag popcnt     && set_feature "popcnt" true
        check_linux_flag fma        && set_feature "fma" true
    fi
fi

# --- aarch64 features ----------------------------------------------------
if [[ "$arch" == "aarch64" ]]; then
    # Initialize all features to false, except neon which is always true
    set_feature "neon" true
    for feat in aes sha2 crc sve sve2; do
        set_feature "$feat" false
    done

    # rustc cfg
    has_rustc_feature "aes"  && set_feature "aes" true
    has_rustc_feature "sha2" && set_feature "sha2" true
    has_rustc_feature "crc"  && set_feature "crc" true
    has_rustc_feature "sve"  && set_feature "sve" true
    has_rustc_feature "sve2" && set_feature "sve2" true

    if [[ "$os" == "darwin" ]]; then
        sysctl_check() {
            local val
            val="$(sysctl -n "$1" 2>/dev/null || true)"
            [[ "$val" == "1" ]]
        }

        sysctl_check hw.optional.neon              && set_feature "neon" true
        sysctl_check hw.optional.AdvSIMD            && set_feature "neon" true
        sysctl_check hw.optional.arm.FEAT_AES       && set_feature "aes" true
        sysctl_check hw.optional.arm.FEAT_SHA256    && set_feature "sha2" true
        sysctl_check hw.optional.arm.FEAT_SHA2      && set_feature "sha2" true
        sysctl_check hw.optional.armv8_crc32        && set_feature "crc" true
        sysctl_check hw.optional.arm.FEAT_CRC32     && set_feature "crc" true
        sysctl_check hw.optional.arm.FEAT_SVE       && set_feature "sve" true
        sysctl_check hw.optional.arm.FEAT_SVE2      && set_feature "sve2" true

    elif [[ "$os" == "linux" ]]; then
        cpu_features="$(grep -m1 '^Features' /proc/cpuinfo 2>/dev/null \
                        | sed 's/.*: //' || true)"

        check_arm_flag() {
            echo " $cpu_features " | grep -q " $1 " 2>/dev/null
        }

        check_arm_flag asimd  && set_feature "neon" true
        check_arm_flag aes    && set_feature "aes" true
        check_arm_flag sha2   && set_feature "sha2" true
        check_arm_flag crc32  && set_feature "crc" true
        check_arm_flag sve    && set_feature "sve" true
        check_arm_flag sve2   && set_feature "sve2" true
    fi
fi

# ---------------------------------------------------------------------------
# Compute max vector width
# ---------------------------------------------------------------------------

max_vector_width_bits=0

if [[ "$arch" == "x86_64" ]]; then
    if [[ "$(get_feature avx512f)" == "true" ]]; then
        max_vector_width_bits=512
    elif [[ "$(get_feature avx2)" == "true" ]] || [[ "$(get_feature avx)" == "true" ]]; then
        max_vector_width_bits=256
    elif [[ "$(get_feature sse2)" == "true" ]]; then
        max_vector_width_bits=128
    fi
elif [[ "$arch" == "aarch64" ]]; then
    if [[ "$(get_feature sve)" == "true" ]] || [[ "$(get_feature sve2)" == "true" ]]; then
        # SVE is scalable; report minimum guaranteed width (128).
        # Actual width varies by implementation (128-2048).
        max_vector_width_bits=128
    elif [[ "$(get_feature neon)" == "true" ]]; then
        max_vector_width_bits=128
    fi
fi

# ---------------------------------------------------------------------------
# Recommendation logic
# ---------------------------------------------------------------------------

recommended_baseline="unknown"
recommended_fast_path="null"    # JSON null
frequency_throttle_risk=false

if [[ "$arch" == "x86_64" ]]; then
    recommended_baseline="sse2"
    if [[ "$(get_feature sse4.2)" == "true" ]]; then
        recommended_baseline="sse4.2"
    fi
    if [[ "$(get_feature avx2)" == "true" ]]; then
        recommended_baseline="avx2"
    fi

    if [[ "$(get_feature avx512f)" == "true" ]]; then
        recommended_fast_path='"avx512"'
    fi

    # Frequency throttle risk: x86 + avx512 + Intel CPU
    if [[ "$(get_feature avx512f)" == "true" ]]; then
        if echo "$cpu_model" | grep -qi "intel" 2>/dev/null; then
            frequency_throttle_risk=true
        fi
    fi

elif [[ "$arch" == "aarch64" ]]; then
    recommended_baseline="neon"

    if [[ "$(get_feature sve2)" == "true" ]]; then
        recommended_fast_path='"sve2"'
    elif [[ "$(get_feature sve)" == "true" ]]; then
        recommended_fast_path='"sve"'
    fi
fi

# ---------------------------------------------------------------------------
# Build final JSON output with jq
# ---------------------------------------------------------------------------

# Sort features keys for deterministic output
features_json="$(echo "$features_json" | jq -S '.')"

jq -n \
    --arg arch "$arch" \
    --arg os "$os" \
    --arg rust_target "$rust_target" \
    --arg cpu_model "$cpu_model" \
    --argjson features "$features_json" \
    --argjson max_vector_width_bits "$max_vector_width_bits" \
    --arg recommended_baseline "$recommended_baseline" \
    --argjson recommended_fast_path "$recommended_fast_path" \
    --argjson frequency_throttle_risk "$frequency_throttle_risk" \
    '{
        arch: $arch,
        os: $os,
        rust_target: $rust_target,
        cpu_model: $cpu_model,
        features: $features,
        max_vector_width_bits: $max_vector_width_bits,
        recommended_baseline: $recommended_baseline,
        recommended_fast_path: $recommended_fast_path,
        frequency_throttle_risk: $frequency_throttle_risk
    }'
