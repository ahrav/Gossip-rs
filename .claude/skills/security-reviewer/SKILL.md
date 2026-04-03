---
name: security-reviewer
description: Use when modifying unsafe blocks, adding parsing or decoding logic, changing buffer pool or scratch internals, or before merging changes to data structure implementations with raw pointers. Memory safety and security audit.
---

# Security Reviewer

Review unsafe code and security-sensitive operations in the gossip-rs codebase.

## When to Use

- After modifying any `unsafe` block
- When adding new parsing or decoding logic
- Before merging changes to data structure internals or buffer handling code
- When implementing new protocol handling or serialization

## Critical Areas in This Codebase

### High-Risk Files
- `crates/gossip-stdx/src/inline_vec.rs` - Stack-backed collection with unsafe pointer ops
- `crates/gossip-stdx/src/ring_buffer.rs` - Fixed-capacity circular queue with unsafe
- `crates/gossip-stdx/src/byte_slab.rs` - Pre-allocated byte pool with raw pointers
- `crates/gossip-connectors/src/filesystem.rs` - Filesystem I/O with unsafe
- `crates/gossip-coordination/src/lib.rs` - Coordination protocol internals

### Scanner Engine High-Risk Files
- `crates/scanner-engine/src/engine/hit_pool.rs` - Sorted hit pool with unsafe pointer ops
- `crates/scanner-engine/src/engine/scratch.rs` - Reusable scratch memory with raw pointers
- `crates/scanner-engine/src/engine/stream_decode.rs` - Streaming decoder with buffer manipulation
- `crates/scanner-engine/src/engine/buffer_scan.rs` - Buffer scanning with unsafe slice ops
- `crates/scanner-engine/src/engine/transform.rs` - Transform/decode pipeline (base64, etc.)
- `crates/scanner-engine/src/engine/vectorscan_prefilter.rs` - FFI boundary with vectorscan
- `crates/scanner-engine/src/scratch_memory.rs` - Scratch memory allocation with raw pointers
- `crates/scanner-engine/src/lsm/set_associative_cache.rs` - Cache with SIMD tag matching
- `crates/scanner-engine/src/engine/simd_classify.rs` - SIMD byte classification

### Scanner Scheduler High-Risk Files
- `crates/scanner-scheduler/src/runtime.rs` - Runtime with async I/O and unsafe
- `crates/scanner-scheduler/src/scheduler/` - Work-stealing scheduler (48 files)

### Scanner Git High-Risk Files
- `crates/scanner-git/src/` - Git pack parsing, delta decoding (86 files with binary data handling)

## Security Checklist

### Memory Safety
- [ ] All pointer arithmetic checked for overflow
- [ ] Slice bounds validated before `get_unchecked`
- [ ] Lifetimes correctly constrain returned references
- [ ] No use-after-free in buffer pool operations
- [ ] Alignment requirements satisfied for casts

### Buffer Handling
- [ ] No buffer overflows in write operations
- [ ] Length checks before copying
- [ ] Integer overflow checks on size calculations
- [ ] Proper handling of truncated reads

### Unsafe Block Audit
For each `unsafe` block:
- [ ] Documented safety invariants (why this is safe)
- [ ] Minimal scope (only unsafe operations inside)
- [ ] Kani proof or extensive testing coverage
- [ ] No undefined behavior paths

### Input Validation
- [ ] Untrusted input length-limited
- [ ] Malformed input cannot cause panics
- [ ] No amplification attacks (small input -> huge allocation)
- [ ] Transform chains handle edge cases (empty, max-size)

## Output Format

```markdown
## Security Review: [file/module]

### Unsafe Block Audit

| Location | Purpose | Safety Justification | Status |
|----------|---------|---------------------|--------|
| line:XX | ptr arithmetic | bounds checked at line:YY | SAFE |
| line:XX | transmute | MISSING JUSTIFICATION | REVIEW |

### Findings

| Severity | Issue | Location | CWE |
|----------|-------|----------|-----|
| CRITICAL | Unchecked bounds | line:XX | CWE-125 |
| HIGH | Integer overflow | line:XX | CWE-190 |

### Recommendations

1. **[Issue]**: Add bounds check before unsafe access
   ```rust
   // Before (unsafe)
   // After (safe)
   ```

### Verification

- [ ] Add Kani proof for memory safety
- [ ] Add fuzz target for this code path
- [ ] Add property test for invariant
```

## Related Resources

- `docs/kani-verification.md` - Existing Kani proofs
- `/test-strategy` - Choose appropriate verification approach
- `/run-fuzz` - Run fuzz targets for security testing
