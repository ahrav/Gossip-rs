# Documentation Rigor Patterns

## What strong docs do

- Open with purpose, scope, and why the module exists.
- State invariants and correctness/safety rules upfront.
- Provide a high-level algorithm or flow before details.
- Explain key design choices and trade-offs (why this approach).
- Call out conservative behavior, limitations, and failure modes.
- Include references to external specs or crates when relevant.

## Template: module-level docs (Rust)

```rust
//! Short title: what this module does.
//!
//! Purpose: where it fits in the system and why it exists.
//!
//! Invariant / safety rule:
//! - ...
//!
//! High-level algorithm:
//! 1. ...
//! 2. ...
//!
//! Design choices:
//! - Why representation/format X.
//! - Limitations or conservative behavior.
//!
//! References:
//! - link or crate docs
```

## Template: type/function docs

```rust
/// Summary in one line.
///
/// Guarantees / invariants:
/// - ...
///
/// Inputs / outputs:
/// - ...
///
/// Errors / edge cases:
/// - ...
///
/// Complexity:
/// - ...
```

## Commenting heuristics

- Prefer explaining intent, invariants, and boundaries over narrating syntax.
- Use numbered steps or short lists for multi-stage logic.
- Put warnings near correctness-critical code paths.
- Add examples only when behavior is subtle or surprising.

## Anti-patterns to avoid

- Paraphrasing code syntax.
- Narrating loops without intent.
- Vague comments ("do stuff", "handle case").

## When to inline-comment

- Explain why a check exists.
- Explain why ordering matters.
- Capture tricky bounds, magic numbers, or proofs.
