---
name: performance-analyzer
description: Analyze Rust code for performance issues, allocation hot spots, and optimization opportunities
---

# Performance Analyzer

Analyze performance-critical code in the gossip-rs workspace (coordination, scanner engine, data structures).

## When to Use

- After writing hot-path code (coordination, scanning, decoding, validation)
- Before committing changes to `crates/scanner-engine/src/engine/` modules
- When benchmark results show unexpected regressions
- During optimization work on data structures in `crates/gossip-stdx/src/`

## Analysis Checklist

### Memory & Allocation
- [ ] Unnecessary allocations in loops (Vec, String, Box)
- [ ] Missing `with_capacity()` for known-size collections
- [ ] Cloning where borrowing would suffice
- [ ] Large structs passed by value instead of reference

### CPU & Cache
- [ ] False sharing in concurrent data structures
- [ ] Cache-unfriendly access patterns (strided, random)
- [ ] Missing `#[inline(always)]` on hot functions
- [ ] Branch-heavy code that could use branchless alternatives

### Async & Concurrency
- [ ] Blocking operations in async contexts
- [ ] Lock contention patterns
- [ ] Oversized futures (check with `std::mem::size_of`)
- [ ] Unnecessary `Arc` when `Rc` or ownership would work

### Rust-Specific
- [ ] Bounds checks in hot loops (consider `get_unchecked` with proof)
- [ ] Iterator vs manual loop performance
- [ ] `&str` vs `String` in function signatures
- [ ] Zero-cost abstraction violations

## Project-Specific Patterns

This codebase uses these performance patterns:
- `NONE_U32 = u32::MAX` as sentinel (avoid Option overhead)
- `#[inline(always)]` on hot-path functions
- `debug_assert!` for invariant checks (zero cost in release)
- Const generics (`G`) for compile-time granularity selection

## Output Format

```markdown
## Performance Analysis: [file/function]

### Findings

| Severity | Issue | Location | Impact |
|----------|-------|----------|--------|
| HIGH | Allocation in hot loop | line:XX | ~Xns per call |
| MEDIUM | Missing inline hint | line:XX | Potential call overhead |

### Recommendations

1. **[Issue]**: [Specific fix with code example]
   ```rust
   // Before
   // After
   ```

### Validation

Run these benchmarks to verify:
- `cargo bench --bench <relevant_bench>`
```

## Related Skills

- `/bench-compare` - Before/after measurement
- `/asm-forge` - ASM-guided optimization
- `/perf-regression` - Full regression workflow
