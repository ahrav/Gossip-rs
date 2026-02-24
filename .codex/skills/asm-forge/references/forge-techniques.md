# Forge Techniques — Rust Source Transforms and Their ASM Impact

Concrete Rust source-level changes and the assembly improvements they produce.
Each technique includes before/after Rust code, expected ASM change, and when to apply.

## Reference Documentation

- **The Rust Performance Book**: https://nnethercote.github.io/perf-book/
- **Rust Compiler Explorer (Godbolt)**: https://godbolt.org/ (verify transforms live)
- **cargo-show-asm**: https://github.com/pacak/cargo-show-asm
- **Rust std library source**: https://doc.rust-lang.org/src/core/ (understand what std does under the hood)
- **LLVM Optimization Passes**: https://llvm.org/docs/Passes.html
- **Criterion.rs User Guide**: https://bheisler.github.io/criterion.rs/book/

**Verification mandate**: After applying any technique, ALWAYS:
1. Collect ASM with `cargo asm` and diff against the before state
2. Run benchmarks with `cargo bench -- --baseline forge-before`
3. Accept only if BOTH ASM and benchmarks confirm improvement

## 1. Bounds Check Elision

### Iterator Instead of Index
```rust
// BEFORE: bounds check on every access
fn sum_slice(data: &[u32]) -> u32 {
    let mut sum = 0;
    for i in 0..data.len() {
        sum += data[i];  // generates: cmp + jae + panic path
    }
    sum
}

// AFTER: iterator — no bounds checks
fn sum_slice(data: &[u32]) -> u32 {
    data.iter().sum()
    // Or equivalently:
    // let mut sum = 0;
    // for &x in data { sum += x; }
    // sum
}
```

**ASM impact**: Removes `cmp + jae/b.hs + call panic` per iteration. Often
enables auto-vectorization that was blocked by the bounds check.

**Verify**: `grep -c panic /tmp/asm-after.s` should show fewer panic paths.

### Chunked Processing
```rust
// BEFORE: multiple indexed accesses per iteration
fn process_pairs(data: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(data.len() / 2);
    for i in (0..data.len()).step_by(2) {
        out.push(u16::from_le_bytes([data[i], data[i + 1]]));  // 2 bounds checks
    }
    out
}

// AFTER: chunks_exact eliminates bounds checks
fn process_pairs(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect()
}
```

**ASM impact**: Removes 2 bounds checks per iteration. Compiler can prove
chunk.len() == 2 at compile time.

### Unsafe get_unchecked (Last Resort)
```rust
// BEFORE: bounds check the compiler can't elide
fn lookup(table: &[u8; 256], input: &[u8], output: &mut [u8]) {
    for i in 0..input.len() {
        output[i] = table[input[i] as usize];  // table access: no check needed (u8 < 256)
                                                 // but compiler may not know table.len() == 256
    }
}

// AFTER: unsafe with safety proof
fn lookup(table: &[u8; 256], input: &[u8], output: &mut [u8]) {
    assert!(output.len() >= input.len());  // one check upfront
    for i in 0..input.len() {
        // SAFETY: input[i] is u8, max value 255. table has exactly 256 entries.
        // output.len() >= input.len() asserted above.
        unsafe {
            *output.get_unchecked_mut(i) = *table.get_unchecked(input[i] as usize);
        }
    }
}
```

**ASM impact**: Removes bounds check per iteration. The upfront assert is checked once.

**Caution**: Always write a `// SAFETY:` comment proving correctness.
Run under Miri (`cargo miri test`) to validate.

## 2. Struct Packing and Layout

### Field Reordering for Size
```rust
// BEFORE: 24 bytes due to alignment padding
struct Entry {
    active: bool,       // 1 byte + 7 padding
    timestamp: u64,     // 8 bytes
    count: u16,         // 2 bytes + 6 padding
}
// size_of::<Entry>() == 24

// AFTER: 16 bytes (or 12 with repr(C))
struct Entry {
    timestamp: u64,     // 8 bytes (naturally aligned)
    count: u16,         // 2 bytes
    active: bool,       // 1 byte + 5 padding to next alignment
}
// size_of::<Entry>() == 16 (Rust compiler) or use #[repr(C)] for explicit control
```

**ASM impact**: Smaller structs → fewer cache lines loaded per array access → better
cache utilization. For an array of 1000 entries: 24KB vs 16KB (fits more in L1).

**Verify**: `std::mem::size_of::<Entry>()` in a test or `println!`.

### Sentinel Values Instead of Option
```rust
// BEFORE: Option<u32> is 8 bytes (4 data + 4 discriminant, or niche if NonZero)
struct Rule {
    gate_a: Option<u32>,  // 8 bytes (u32 has no niche)
    gate_b: Option<u32>,  // 8 bytes
    gate_c: Option<u32>,  // 8 bytes
}
// 24 bytes for 3 optional u32 values

// AFTER: sentinel value, 4 bytes each
const NO_GATE: u32 = u32::MAX;  // sentinel: "no gate assigned"
struct Rule {
    gate_a: u32,  // 4 bytes, NO_GATE means absent
    gate_b: u32,  // 4 bytes
    gate_c: u32,  // 4 bytes
}
// 12 bytes for 3 optional u32 values

// Check with:
fn has_gate_a(&self) -> bool { self.gate_a != NO_GATE }
```

**ASM impact**: Eliminates discriminant checks. `cmp reg, 0xFFFFFFFF` is simpler
than option match codegen. Struct is 50% smaller.

**This project already uses this pattern** (`NONE_U32 = u32::MAX`).

### Hot/Cold Field Separation
```rust
// BEFORE: hot and cold fields interleaved
struct Rule {
    // Hot: accessed every scan
    regex_id: u32,
    must_contain: PackedPatterns,
    // Cold: accessed only on match
    name: String,
    description: String,
    severity: Severity,
    tags: Vec<String>,
}

// AFTER: separate hot and cold paths
struct RuleHot {
    regex_id: u32,
    must_contain: PackedPatterns,
    cold_idx: u32,  // index into cold array
}

struct RuleCold {
    name: String,
    description: String,
    severity: Severity,
    tags: Vec<String>,
}
```

**ASM impact**: Hot path iterates over smaller structs → more fit in cache line →
fewer cache misses. Cold data only touched on match (rare path).

**This project already uses this pattern** (`RuleCompiled` + `RuleCold`).

## 3. Branchless Techniques

### Conditional Move via min/max
```rust
// BEFORE: branch
fn clamp_to_max(x: u32, max: u32) -> u32 {
    if x > max { max } else { x }
}
// Generates: cmp + jbe + mov (branch)

// AFTER: branchless
fn clamp_to_max(x: u32, max: u32) -> u32 {
    x.min(max)
}
// Generates: cmp + cmov (x86-64) or csel (AArch64) — no branch
```

### Lookup Table Instead of Match
```rust
// BEFORE: match with many arms (generates jump table or branch chain)
fn category(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => 1,
        b'a'..=b'z' | b'A'..=b'Z' => 2,
        b' ' | b'\t' | b'\n' | b'\r' => 3,
        _ => 0,
    }
}

// AFTER: lookup table (single indexed load, no branches)
static CATEGORY: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = match i as u8 {
            b'0'..=b'9' => 1,
            b'a'..=b'z' | b'A'..=b'Z' => 2,
            b' ' | b'\t' | b'\n' | b'\r' => 3,
            _ => 0,
        };
        i += 1;
    }
    t
};

fn category(byte: u8) -> u8 {
    CATEGORY[byte as usize]  // single load, no bounds check (u8 always < 256)
}
```

**ASM impact**: Replaces N comparisons + branches with 1 memory load. If the table
fits in L1 cache (256 bytes = 4 cache lines), this is always faster for unpredictable
input.

### Bit Manipulation Instead of Branches
```rust
// BEFORE: branching boolean check
fn any_flag_set(flags: u32, mask: u32) -> bool {
    if flags & mask != 0 { true } else { false }
}

// AFTER: branchless (compiler often does this, but check)
fn any_flag_set(flags: u32, mask: u32) -> bool {
    (flags & mask) != 0
    // If used in further computation, consider keeping as u32:
    // (flags & mask).min(1) to get 0 or 1 without branch
}
```

## 4. ILP Exploitation

### Multiple Accumulators
```rust
// BEFORE: single accumulator (serial dependency chain)
fn count_matches(data: &[u8], target: u8) -> usize {
    let mut count = 0;
    for &byte in data {
        if byte == target { count += 1; }
    }
    count
}

// AFTER: 4 independent accumulators (4x ILP)
fn count_matches(data: &[u8], target: u8) -> usize {
    let (mut c0, mut c1, mut c2, mut c3) = (0usize, 0, 0, 0);
    let chunks = data.chunks_exact(4);
    let remainder = chunks.remainder();
    for chunk in chunks {
        c0 += (chunk[0] == target) as usize;
        c1 += (chunk[1] == target) as usize;
        c2 += (chunk[2] == target) as usize;
        c3 += (chunk[3] == target) as usize;
    }
    let mut count = c0 + c1 + c2 + c3;
    for &byte in remainder {
        count += (byte == target) as usize;
    }
    count
}
```

**ASM impact**: 4 independent `add` chains instead of 1. CPU can overlap them
with out-of-order execution. On wide CPUs (Apple M-series: 6 ALUs), this can
approach 4x speedup.

### Hoisting Invariant Computations
```rust
// BEFORE: recomputed every iteration
fn process(data: &[u8], config: &Config) {
    for &byte in data {
        let threshold = config.base + config.offset * 2;  // invariant!
        if byte > threshold as u8 {
            // ...
        }
    }
}

// AFTER: hoisted out of loop
fn process(data: &[u8], config: &Config) {
    let threshold = (config.base + config.offset * 2) as u8;  // computed once
    for &byte in data {
        if byte > threshold {
            // ...
        }
    }
}
```

**Note**: LLVM usually handles this (Loop Invariant Code Motion / LICM), but
sometimes aliasing or side effects prevent it. If you see redundant computation
in the ASM loop body, the compiler failed to hoist. Help by making the invariant
explicit.

### Breaking Pointer Chasing
```rust
// BEFORE: linked list traversal (pointer chase, no ILP)
fn sum_list(head: &Node) -> u32 {
    let mut sum = 0;
    let mut current = head;
    loop {
        sum += current.value;           // depends on current (load latency)
        match current.next.as_ref() {   // depends on current (another load)
            Some(next) => current = next,
            None => break,
        }
    }
    sum
}

// AFTER: flatten to array (sequential access, prefetch-friendly)
fn sum_array(values: &[u32]) -> u32 {
    values.iter().sum()
}
```

**ASM impact**: Sequential memory access enables hardware prefetcher. CPU can
predict and preload the next cache line. Pointer chasing forces the CPU to wait
for each load before knowing the next address.

## 5. Inline Hinting

### Hot Functions
```rust
// Add to small, frequently-called functions that aren't being inlined
#[inline(always)]
fn is_ascii_digit(b: u8) -> bool {
    b.wrapping_sub(b'0') < 10
}
```

**When to use**: If the ASM shows a `call/bl` to a function that's <10 instructions,
and it's in a hot loop, `#[inline(always)]` forces inlining.

**When NOT to use**: Large functions (>50 instructions). Inlining them bloats the
caller and can hurt icache performance. Use `#[inline]` (hint, not forced) instead.

### Cold Functions
```rust
// Mark error paths and rare branches
#[cold]
#[inline(never)]
fn handle_error(err: Error) -> ! {
    panic!("unexpected error: {err}");
}

// Usage in hot path:
fn process(data: &[u8]) -> Result<(), Error> {
    if data.is_empty() {
        handle_error(Error::Empty);  // cold: compiler moves this code away
    }
    // ... hot path continues with better code layout
    Ok(())
}
```

**ASM impact**: `#[cold]` tells the compiler to:
- Move this code to a distant section (out of the hot loop's icache footprint)
- Optimize the *other* path (the hot path) preferentially
- Not inline this function into callers

### Verify Inlining
```bash
# Check if a function was inlined — it shouldn't appear as a separate symbol:
cargo asm --lib -p scanner-rs 2>&1 | grep 'function_name'
# If it appears: not inlined. If absent: successfully inlined into callers.

# To see where it was inlined, use --rust mode on the caller:
cargo asm --lib -p scanner-rs --rust 'caller_function'
# Inlined code will appear as interleaved source from the callee.
```

## 6. SIMD Assistance

### Helping Auto-Vectorization
```rust
// BEFORE: loop body has a function call (blocks vectorization)
fn transform(data: &mut [f32]) {
    for x in data.iter_mut() {
        *x = process(*x);  // if process() isn't inlined, can't vectorize
    }
}

// AFTER: inline the operation (enables vectorization)
#[inline(always)]
fn process(x: f32) -> f32 {
    x * 2.0 + 1.0  // simple arithmetic: vectorizable
}

fn transform(data: &mut [f32]) {
    for x in data.iter_mut() {
        *x = process(*x);  // now inlined: loop body is pure arithmetic
    }
}
```

### Explicit Alignment for SIMD
```rust
// Ensure data is aligned for SIMD loads
#[repr(C, align(32))]  // 32-byte alignment for AVX2
struct AlignedBuffer {
    data: [u8; 256],
}
```

### Checking Vectorization
```bash
# Verify SIMD instructions were emitted:
# x86-64: look for v-prefixed instructions (AVX) or packed ops (SSE)
cargo asm --lib -p scanner-rs 'function' | grep -E 'vmov|vpadd|vpcmp|vadd|vmul|vpshuf'

# AArch64: look for NEON instructions (vector register operands)
cargo asm --lib -p scanner-rs 'function' | grep -E '\.16b|\.8h|\.4s|\.2d|v[0-9]+\.'

# If no SIMD instructions, check LLVM-IR for vectorization failure reasons:
RUSTFLAGS="-C target-cpu=native -C llvm-args=-pass-remarks-missed=loop-vectorize" \
  cargo build --release 2>&1 | grep 'remark'
```

## 7. Memory Traffic Reduction

### Avoid Redundant Loads
```rust
// BEFORE: field accessed through reference multiple times
fn process(entry: &Entry) -> u64 {
    let a = entry.timestamp * 2;       // load entry.timestamp
    let b = entry.timestamp + 100;     // load entry.timestamp AGAIN
    a + b
}

// AFTER: load once into local (helps compiler keep in register)
fn process(entry: &Entry) -> u64 {
    let ts = entry.timestamp;          // single load
    let a = ts * 2;                    // register
    let b = ts + 100;                  // register
    a + b
}
```

**Note**: LLVM usually handles this for simple cases. But through pointers, trait
objects, or across function calls (especially with `&mut` aliasing concerns), the
compiler may reload defensively. Local variables eliminate ambiguity.

### Batch Field Access
```rust
// BEFORE: access struct fields one at a time through a slice
fn sum_timestamps(entries: &[Entry]) -> u64 {
    entries.iter().map(|e| e.timestamp).sum()
}

// If this is truly the hot path and Entry is large, consider SoA:
struct Entries {
    timestamps: Vec<u64>,
    // ... other fields in separate vecs
}

fn sum_timestamps(entries: &Entries) -> u64 {
    entries.timestamps.iter().sum()  // perfect sequential access
}
```

## Technique Selection Guide

| Symptom in ASM | Technique | Expected Impact |
|---|---|---|
| `panic_bounds_check` in loop | Bounds check elision (#1) | 5-30% |
| Many `[rsp+N]` accesses | Struct packing (#2) or function splitting | 5-15% |
| Serial `add/mul` chains | Multiple accumulators (#4) | 20-60% |
| `cmp + je/jne` in inner loop | Branchless techniques (#3) | 5-25% |
| Scalar loop on array data | SIMD assistance (#6) | 2-16x |
| `call` in inner loop | Inline hinting (#5) | 5-20% |
| Redundant `ldr/mov` | Memory traffic reduction (#7) | 3-10% |
| Large function prologue (many pushes) | Function splitting + `#[cold]` | 5-15% |

## Verification Protocol

For every technique applied:

1. **Before ASM**: `cargo asm --lib -p scanner-rs --rust 'fn' > /tmp/asm-before.s`
2. **Apply change**
3. **After ASM**: `cargo asm --lib -p scanner-rs --rust 'fn' > /tmp/asm-after.s`
4. **Diff**: `diff /tmp/asm-before.s /tmp/asm-after.s`
5. **Benchmark**: `cargo bench --bench <name> -- --baseline forge-before`
6. **Tests**: `cargo test` (ensure correctness preserved)
7. **Cross-ISA** (if applicable): Repeat on both x86-64 and AArch64
8. **Godbolt spot-check**: Paste the hot function into https://godbolt.org/ with
   `rustc nightly -O -C target-cpu=native` to independently verify codegen
