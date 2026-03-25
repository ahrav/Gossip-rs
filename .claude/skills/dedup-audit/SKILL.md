---
name: dedup-audit
description: Systematic multi-pass code deduplication audit for Rust workspaces. Use when duplication has accumulated across crates, when error boilerplate is excessive, when repeated From/Display/Error impls appear across modules, when onboarding thiserror, or when establishing CI duplication gates. Triggers on "find duplicates", "reduce duplication", "dedup audit", "thiserror migration", "error boilerplate".
---

# Dedup Audit

Multi-pass deduplication campaign for Rust workspaces. Detects duplicates with
two complementary tools, triages true vs incidental duplication, eliminates
error boilerplate via thiserror, extracts macros for repeated routing impls,
and installs CI prevention gates.

**Core principle:** Syntactic similarity is not semantic identity. Every tool
report requires human triage before action. The wrong abstraction costs more
than the duplication it removes.

## When to Use

- Error boilerplate has accumulated (hand-written Display, Error, From impls)
- Cross-crate structural duplication is suspected but unquantified
- Starting a thiserror migration
- Setting up CI duplication gates for the first time
- Periodic code health audit (quarterly recommended)

## When NOT to Use

- Single-file refactoring (just fix it directly)
- Test-only duplication (higher thresholds apply; test clarity > DRY)
- Two instances of similar code (wait for the rule of three)

---

## Pass 1: Detection Baseline

Run both tools to get complementary views. Token-based catches broad patterns;
AST-based catches structural clones with higher precision.

### 1a. Install Tools

```bash
npm install -g jscpd        # Token-based, 150+ languages
cargo install cargo-dupes    # AST-based, Rust-native via syn
```

### 1b. Token-Level Scan (jscpd)

```bash
mkdir -p tmp/dedup-baseline
jscpd --min-tokens 50 --min-lines 5 \
  --reporters json,html \
  --ignore "target/**,fuzz/**,tmp/**" \
  --format rust \
  --output tmp/dedup-baseline \
  crates/
```

Parse results:
```bash
python3 -c "
import json, sys
data = json.load(open('tmp/dedup-baseline/jscpd-report.json'))
s = data['statistics']['total']
print(f'Duplication: {s[\"percentage\"]}% ({s[\"duplicatedLines\"]} lines, {s[\"clones\"]} pairs)')
"
```

**Industry target:** <5% for production code. 5-10% warrants review. >10% demands action.

### 1c. AST-Level Scan (cargo-dupes)

```bash
# High threshold: near-exact clones
cargo dupes report --threshold 0.9 --exclude-tests --min-nodes 15 \
  > tmp/dedup-baseline/cargo-dupes-exact.txt

# Lower threshold: structural similarity
cargo dupes report --threshold 0.7 --exclude-tests --min-nodes 20 \
  > tmp/dedup-baseline/cargo-dupes-similar.txt
```

If cargo-dupes OOMs on large workspaces, run per-crate:
```bash
for crate in crates/*/; do
  cargo dupes report --threshold 0.9 --path "$crate" 2>/dev/null
done
```

### 1d. Triage

For each clone pair, apply the **incidental duplication test**:

> "If I change this code for caller A's requirements, must caller B also change?"
> - **Yes** -> true duplication, actionable
> - **No** -> incidental duplication, leave it alone

Categorize every detected pair as: **true-duplication** / **intentional** / **deferred**

**Common intentional duplication in Rust:**
- Per-operation error enums with overlapping variants (compile-time exhaustiveness)
- Sync/async trait pairs with identical signatures
- Custom Debug impls with different redaction policies
- Benchmark/test closures

---

## Pass 2: Error Boilerplate Elimination

Error handling boilerplate is consistently the largest actionable duplication
category in Rust workspaces. This pass is mechanical and low-risk.

### 2a. Add thiserror to Workspace

```toml
# Root Cargo.toml
[workspace.dependencies]
thiserror = "2"
```

### 2b. Convert Error Types WITHOUT Custom Debug

For types with `#[derive(Debug)]` (standard Debug), the conversion is:

```rust
// BEFORE:
#[derive(Debug)]
pub enum FooError {
    Bar(BarError),
    Baz { detail: String },
}
impl fmt::Display for FooError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bar(e) => write!(f, "bar failed: {e}"),
            Self::Baz { detail } => write!(f, "baz: {detail}"),
        }
    }
}
impl std::error::Error for FooError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Bar(e) => Some(e), _ => None }
    }
}

// AFTER:
#[derive(Debug, thiserror::Error)]
pub enum FooError {
    #[error("bar failed: {0}")]
    Bar(#[source] BarError),
    #[error("baz: {detail}")]
    Baz { detail: String },
}
```

**Rules:**
- `#[source]` where `source()` returns `Some(inner)` but no `From` impl exists
- `#[from]` ONLY where an existing `From` impl is being replaced
- Fields named `source` are auto-detected by thiserror (no annotation needed)
- Preserve exact Display format strings
- Remove hand-written Display, Error, and replaced From impls
- Remove unused `use std::fmt` / `use std::error::Error` imports
- One crate per PR to keep diffs reviewable

### 2c. Convert Error Types WITH Custom Debug (Redaction)

thiserror v2 does NOT auto-derive Debug. Custom Debug impls for security
redaction (hiding hash values, keys, credentials) are safe alongside thiserror:

```rust
#[derive(Clone, PartialEq, Eq, thiserror::Error)]  // NO Debug here
#[non_exhaustive]
pub enum SecretError {
    #[error("connection failed to {host}")]
    Connection { host: String, #[source] source: io::Error },
}
// Custom Debug with redaction remains untouched
impl fmt::Debug for SecretError { /* redacts host */ }
```

### 2d. Complex Display Logic

When `#[error("...")]` cannot express the formatting (conditional logic,
method calls, helper functions), keep manual Display but still derive
`thiserror::Error` for the Error impl:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ComplexError {
    // No #[error] attributes — manual Display below
    Variant { source: InnerError },  // source auto-detected
}
impl fmt::Display for ComplexError { /* complex logic */ }
```

### 2e. Macro Extraction for Repeated From Routing

When 3+ `From<SharedError> for SpecificError` impls follow the same pattern
(accept some variants, reject others with `unreachable!()`), extract a macro:

```rust
macro_rules! impl_from_shared_error {
    ($target:ident,
     accept: [ $($variant:ident $({ $($field:ident),* })?),* $(,)? ],
     reject: [ $($rej:pat),* $(,)? ]
    ) => {
        impl From<SharedError> for $target {
            fn from(e: SharedError) -> Self {
                match e {
                    $( SharedError::$variant $({ $($field),* })? =>
                       Self::$variant $({ $($field),* })?, )*
                    $( $rej => unreachable!(
                        "SharedError variant not valid for {}", stringify!($target)
                    ), )*
                }
            }
        }
    };
}
```

**Critical:** Use explicit rejection arms (not wildcards) to preserve
compile-time exhaustiveness. Adding a new variant to `SharedError` must
force a compile error in every routing impl.

Similarly for `From<XxxError> for RejectionKind` patterns in simulation
harnesses.

---

## Pass 3: Structural Assessment

Review remaining duplicates flagged by cargo-dupes near-duplicate detection.

**Decision framework for each candidate:**

```
Is it test/bench code?
  Yes -> Higher threshold applies. Leave it unless it causes maintenance pain.
  No  -> Continue.

Rule of three: Are there 3+ instances?
  No  -> Defer. Two instances are insufficient signal.
  Yes -> Continue.

Can you name the abstraction clearly?
  No  -> The abstraction is premature. Leave the duplication.
  Yes -> Continue.

Would extraction introduce lifetime complexity or generics on hot paths?
  Yes -> Keep concrete. Use the "outline pattern" if generics are needed.
  No  -> Extract.
```

**Rust-specific extraction risks:**
- Generics on hot paths cause monomorphization bloat (n * m code copies)
- Abstracting over borrow/own requires HRTBs/GATs — avoid unless experienced
- Cross-crate extraction may create circular dependencies (Cargo forbids cycles)
- Proc macros add debugging opacity — prefer `macro_rules!`

---

## Pass 4: Prevention Infrastructure

### 4a. jscpd CI Gate

Create `.jscpd.json` at workspace root:

```json
{
  "threshold": 6,
  "reporters": ["json", "consoleFull"],
  "ignore": ["target/**", "fuzz/**", "tmp/**"],
  "minTokens": 50,
  "minLines": 5,
  "format": ["rust"],
  "overrides": [{
    "paths": ["**/*test*", "**/*tests*", "**/benches/**"],
    "minTokens": 100,
    "minLines": 10
  }]
}
```

Start threshold at current baseline + 1% margin. Ratchet down after each pass.

### 4b. CLAUDE.md / Project Policy

Add to project instructions:
- Error types MUST use `#[derive(thiserror::Error)]`
- New routing From impls MUST use the project's routing macro
- Test code is exempt from duplication thresholds

---

## Verification Checklist

After each pass:

```bash
cargo fmt --all
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace  # exclude Docker-dependent crates if needed
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Specific checks:
- `format!("{}", error)` output identical before/after for every converted variant
- `format!("{:?}", error)` still shows `<redacted>` where custom Debug exists
- `error.source()` chain preserved
- After macro introduction, temporarily add a dummy variant to the shared error
  and verify compile error in all routing impls

---

## Quick Reference

| What | Tool/Technique |
|------|---------------|
| Token-level scan | `jscpd --format rust --min-tokens 50` |
| AST-level scan | `cargo dupes report --threshold 0.9` |
| Error boilerplate | `thiserror = "2"` derive macro |
| Routing From impls | `macro_rules!` with accept/reject lists |
| CI gate | `.jscpd.json` with threshold ratchet |
| Pattern enforcement | `ast-grep` rules post-dedup |
| Binary bloat check | `cargo bloat --release` |

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Merging incidental duplication | Apply the "caller A / caller B" test first |
| Using `#[from]` speculatively | Only replace existing `From` impls |
| Mixing refactoring with feature work | Pure refactoring PRs only |
| One giant PR for all conversions | One crate per PR |
| Deduplicating test code aggressively | Test clarity > DRY |
| Using generics on hot paths | Keep concrete; use outline pattern |
| Wildcard rejection in routing macros | Use explicit arms for exhaustiveness |
