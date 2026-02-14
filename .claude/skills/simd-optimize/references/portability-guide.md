# Portable SIMD in Rust

Reference for writing cross-platform SIMD code that compiles and runs correctly
on x86-64, AArch64, and scalar-fallback targets. Covers compile-time dispatch,
runtime feature detection, the `#[target_feature]` attribute, and crate-level
alternatives.

## Static Dispatch with `cfg`

### Architecture Gates

```rust
#[cfg(target_arch = "x86_64")]
mod x86_impl { /* std::arch::x86_64::* intrinsics */ }

#[cfg(target_arch = "aarch64")]
mod arm_impl { /* std::arch::aarch64::* intrinsics */ }

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod scalar_impl { /* Pure scalar fallback */ }
```

### Feature-Level Gates

`cfg(target_feature = "...")` is `true` only at **compile time** when:
- The target implies it (`x86_64` always implies `sse2`)
- The user passes `-C target-feature=+avx2`
- The user passes `-C target-cpu=haswell` (implies AVX2, FMA, BMI2, etc.)

```rust
#[cfg(target_feature = "avx2")]
fn fast_path(data: &[u8]) -> u64 { /* AVX2 guaranteed at compile time */ todo!() }
```

**Important**: This reflects what the *compiler was told*, not what the
runtime CPU supports. For runtime detection, use `is_*_feature_detected!`.

### Combining Conditions

```rust
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
fn optimized() { /* AVX2 guaranteed at compile time */ }

#[cfg(all(target_arch = "x86_64", not(target_feature = "avx2")))]
fn optimized() { /* SSE2 fallback for x86_64 without compile-time AVX2 */ }

#[cfg(target_arch = "aarch64")]
fn optimized() { /* NEON -- always available on AArch64 */ }
```

## `#[target_feature]` Attribute

Tells the compiler to emit instructions for a specific feature set **within
that one function**, even if the rest of the binary targets a baseline ISA.

```rust
#[target_feature(enable = "avx2")]
unsafe fn process_avx2(data: &[u8]) -> u64 {
    use std::arch::x86_64::*;
    // Compiler WILL emit AVX2 instructions here even if the crate
    // targets baseline x86_64 (SSE2 only).
    todo!()
}
```

### Safety Model

Calling a `#[target_feature]` function on a CPU lacking the feature is
**undefined behavior**. The `unsafe` is on the *call site* -- the function
body itself can contain only safe code.

```rust
#[target_feature(enable = "avx2")]
unsafe fn helper() -> i32 { 42 }

#[target_feature(enable = "avx2")]
unsafe fn caller() -> i32 {
    helper()  // Safe: same feature level, no extra unsafe needed.
}

fn dispatch() {
    unsafe { caller() }  // UNSAFE: caller must verify AVX2 is present.
}
```

### Stacking Features

```rust
#[target_feature(enable = "avx2,bmi2")]
unsafe fn combined(data: &[u8]) { todo!() }
```

Feature implications are respected: `avx2` implies `avx` implies `sse4.2`
implies `sse4.1`, etc.

### Restrictions

- Cannot combine with `#[inline(always)]`
- Cannot apply to `main`, `panic_handler`, or safe trait method impls
- Functions with `#[target_feature]` do not implement `Fn`/`FnMut`/`FnOnce`
  (closures defined *inside* the function do inherit the feature)

## Runtime Feature Detection

### x86: `is_x86_feature_detected!`

Stable since Rust 1.27. Queries CPUID on first call, then **caches the
result** in a static -- subsequent calls are a branch on a static `bool`.

```rust
if is_x86_feature_detected!("avx2") {
    unsafe { process_avx2(data) }
} else if is_x86_feature_detected!("sse4.1") {
    unsafe { process_sse41(data) }
} else {
    process_scalar(data)
}
```

Common strings: `sse`, `sse2`, `sse3`, `ssse3`, `sse4.1`, `sse4.2`, `avx`,
`avx2`, `avx512f`, `avx512bw`, `fma`, `bmi1`, `bmi2`, `popcnt`, `lzcnt`.

**Compile-time elision**: When the feature is known via `-C target-feature`,
the macro expands to `true` -- zero runtime cost.

### AArch64: `is_aarch64_feature_detected!`

Stable since Rust 1.61. On Linux, reads `HWCAP`/`HWCAP2`.

**Critical fact**: NEON is mandatory on AArch64 -- every AArch64 CPU has it.
You do **not** need runtime detection for NEON. Use `cfg(target_arch =
"aarch64")` directly. Runtime detection is only needed for optional
extensions (SVE, SVE2, crypto).

**macOS caveat**: `is_aarch64_feature_detected!` may return `false` on
non-Linux platforms even for present features. On Apple Silicon, always gate
NEON on `cfg(target_arch = "aarch64")`, not the runtime macro.

## Fallback Chain Pattern

Complete `sum_bytes` with full dispatch -- the recommended pattern for this
codebase. Uses `OnceLock` function pointers for hot-path dispatch.

```rust
use std::sync::OnceLock;

// ---- x86-64 implementations ----

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sum_bytes_avx2(data: &[u8]) -> u64 {
    use std::arch::x86_64::*;
    let mut total: u64 = 0;
    let mut offset = 0;
    // SAD against zero produces u16 partial sums per 64-bit lane.
    while offset + 32 <= data.len() {
        let chunk = _mm256_loadu_si256(data.as_ptr().add(offset) as *const __m256i);
        let sad = _mm256_sad_epu8(chunk, _mm256_setzero_si256());
        total += _mm256_extract_epi64(sad, 0) as u64;
        total += _mm256_extract_epi64(sad, 1) as u64;
        total += _mm256_extract_epi64(sad, 2) as u64;
        total += _mm256_extract_epi64(sad, 3) as u64;
        offset += 32;
    }
    for i in offset..data.len() { total += data[i] as u64; }
    total
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn sum_bytes_sse2(data: &[u8]) -> u64 {
    use std::arch::x86_64::*;
    let mut total: u64 = 0;
    let mut offset = 0;
    while offset + 16 <= data.len() {
        let chunk = _mm_loadu_si128(data.as_ptr().add(offset) as *const __m128i);
        let sad = _mm_sad_epu8(chunk, _mm_setzero_si128());
        total += _mm_extract_epi64(sad, 0) as u64;
        total += _mm_extract_epi64(sad, 1) as u64;
        offset += 16;
    }
    for i in offset..data.len() { total += data[i] as u64; }
    total
}

// ---- AArch64 implementation ----

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn sum_bytes_neon(data: &[u8]) -> u64 {
    use std::arch::aarch64::*;
    let mut acc = vdupq_n_u16(0);
    let mut offset = 0;
    while offset + 16 <= data.len() {
        let v = vld1q_u8(data.as_ptr().add(offset));
        acc = vpadalq_u8(acc, v);  // pairwise add u8 -> u16
        offset += 16;
    }
    let total = vaddlvq_u16(acc) as u64;
    let mut rem: u64 = 0;
    for i in offset..data.len() { rem += data[i] as u64; }
    total + rem
}

// ---- Scalar fallback ----

fn sum_bytes_scalar(data: &[u8]) -> u64 {
    data.iter().map(|&b| b as u64).sum()
}

// ---- Dispatch via OnceLock function pointer ----

type SumFn = fn(&[u8]) -> u64;
static SUM_DISPATCH: OnceLock<SumFn> = OnceLock::new();

fn resolve_sum() -> SumFn {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return |d| unsafe { sum_bytes_avx2(d) };
        }
        // SSE2 is baseline on x86_64 -- always available.
        return |d| unsafe { sum_bytes_sse2(d) };
    }
    #[cfg(target_arch = "aarch64")]
    {
        // NEON is mandatory -- no runtime check needed.
        return |d| unsafe { sum_bytes_neon(d) };
    }
    #[allow(unreachable_code)]
    { sum_bytes_scalar as SumFn }
}

/// Sum all bytes in `data`. Dispatches to the best SIMD path available.
pub fn sum_bytes(data: &[u8]) -> u64 {
    let f = SUM_DISPATCH.get_or_init(resolve_sum);
    f(data)
}
```

**Key points**:
- On x86-64, `is_x86_feature_detected!` selects the best path at runtime.
- On AArch64, NEON is always present -- `cfg(target_arch)` is sufficient.
- The scalar fallback covers any architecture not explicitly handled.
- Each `#[target_feature]` function is `unsafe` to call; the dispatch
  function is the single place where we establish the safety invariant.

## Function Pointer Dispatch vs Static Dispatch

| Approach | Pros | Cons |
|----------|------|------|
| If-chain (`is_*_detected!`) | No indirection, branch predictor helps | Re-checks cached bool each call |
| `OnceLock` fn pointer | Single init, cached forever | Indirect call, no inlining possible |
| Compile-time `cfg` only | Zero overhead, full inlining | Single target per binary |

**When to use which**:
- **If-chain**: Good default. Cached bool + predicted branch is near-free.
- **OnceLock pointer**: Millions of calls in tight loops, or complex multi-tier dispatch.
- **Compile-time cfg**: Best perf. Use when you control the deploy target.

**Recommendation**: Start with the if-chain. Move to `OnceLock` only if
profiling shows the dispatch branch matters. Use `cfg` for target-locked builds.

## Portable SIMD Crates

### `std::simd` (portable_simd) -- Nightly Only

Status (Feb 2026): nightly-only, `#![feature(portable_simd)]`. No
stabilization timeline. Cross-platform by design: `Simd<T, N>` compiles to
optimal instructions per target, falls back to scalar elsewhere.

```rust
#![feature(portable_simd)]
use std::simd::prelude::*;

fn dot_product(a: &[f32], b: &[f32]) -> f32 {
    let mut sum = f32x8::splat(0.0);
    for (va, vb) in a.chunks_exact(8).zip(b.chunks_exact(8)) {
        sum += f32x8::from_slice(va) * f32x8::from_slice(vb);
    }
    sum.reduce_sum() // + handle remainder
}
```

### `multiversion` Crate

Attribute macros for automatic function multi-versioning on stable Rust.
Clones the function body per target, applies `#[target_feature]`, generates
a cached runtime dispatcher.

```rust
use multiversion::multiversion;

#[multiversion(targets("x86_64+avx2", "x86_64+sse4.1", "aarch64+neon"))]
fn square(x: &mut [f32]) {
    for v in x { *v *= *v; }
}
```

Best for auto-vectorizable loops. LLVM optimizes each clone for its target.

### `wide` Crate

Portable SIMD types on stable Rust (`f32x4`, `f32x8`, `i32x4`, `u8x16`).
**Compile-time dispatch only** -- no runtime detection. Uses `safe_arch`
intrinsics on x86/aarch64/wasm32; auto-vectorizable scalar code elsewhere.

### `pulp` Crate

Type-safe runtime SIMD dispatch with a safe API (no `unsafe` at call sites).

```rust
let arch = pulp::Arch::new();  // runtime detection
arch.dispatch(|| { /* auto-dispatched to best SIMD */ });
```

### Comparison

| Crate | Stable | Runtime Dispatch | Intrinsics | Portability | Ease |
|-------|:------:|:----------------:|:----------:|:-----------:|:----:|
| `std::arch` | Yes | Manual | Full | Per-arch | Low |
| `std::simd` | No | No | No | All targets | High |
| `multiversion` | Yes | Automatic | No | Multi-arch | High |
| `wide` | Yes | No | No | Multi-arch | Med |
| `pulp` | Yes | Automatic | Via traits | Multi-arch | Med |

**Guidance**: For maximum performance, use `std::arch` intrinsics with manual
dispatch (the fallback chain pattern). Use `multiversion` for simple loops
where auto-vectorization is sufficient.

## Recommended Project Layout

```
src/
  simd/
    mod.rs              -- public API + dispatch functions
    scalar.rs           -- pure scalar fallbacks (always compiles)
    x86_avx2.rs         -- #[cfg(target_arch = "x86_64")] + target_feature avx2
    x86_sse2.rs         -- #[cfg(target_arch = "x86_64")] + target_feature sse2
    aarch64_neon.rs     -- #[cfg(target_arch = "aarch64")] + target_feature neon
```

Each file is gated with `#[cfg(target_arch)]` at the module level. The
`mod.rs` dispatch layer uses runtime detection on x86-64 and compile-time
gates on AArch64. This keeps implementations isolated and testable.
