# Technique Catalog

12 complexity reduction techniques organized by automation confidence level. For each:
preconditions (when to suggest), contraindications (when NOT to suggest), and a
presentation template.

---

## Fully Automatable (5 techniques)

### 1. Guard Clauses / Early Return

**Confidence:** `auto-apply`

**Preconditions:**
- Function body is wrapped in `if condition { ... long body ... }`
- The condition is a precondition check (None, bounds, state)
- The else branch is empty, a simple return, or absent

**Contraindications:**
- Both arms have substantial logic (this is an if-else, not a guard)
- Function is inside `unsafe` where early return could skip invariant restoration

**Template:**
```
SUGGESTION: Convert to guard clause (auto-apply)

The if-block at line N wraps M lines of code. Inverting the condition and
returning early reduces nesting by 1 level:

  if <inverted_condition> { return <value>; }
  // ... M lines at reduced nesting ...

Impact: -1 nesting level for M lines.
```

---

### 2. Redundant Else Removal

**Confidence:** `auto-apply`

**Preconditions:**
- An `if` block ends with `return`, `continue`, `break`, or `?` propagation
- An `else` block follows immediately

**Contraindications:**
- The else introduces bindings used after the if-else (scope change)
- The if-else symmetry is intentional documentation (parallel case handling)

**Template:**
```
SUGGESTION: Remove redundant else (auto-apply)

The if-branch at line N returns/breaks. The else keyword and braces can be
removed, reducing nesting by 1 level for N remaining lines.
```

---

### 3. Remove Unnecessary Result

**Confidence:** `auto-apply`

**Preconditions:**
- Function returns `Result<T>` or `Result<T, E>`
- No code path returns `Err(...)`
- Not a trait implementation (where the signature is fixed)

**Contraindications:**
- Trait method implementation (Result required by trait)
- Intentional for future extensibility (check for TODO comments)
- Public API where removing Result is a breaking change

**Template:**
```
SUGGESTION: Remove unnecessary Result (auto-apply)

fn X() -> Result<T> never returns Err. The Result wrapper forces callers to
handle an impossible error. Consider returning T directly.

Note: Breaking change for public APIs. Callers using `?` need updating.
```

---

### 4. Pass by Reference

**Confidence:** `suggest`

**Preconditions:**
- Parameter takes ownership (String, Vec, PathBuf, etc.)
- Parameter is only read inside the function (no move, no return)

**Contraindications:**
- Parameter is `Clone + 'static` and the function spawns async tasks capturing it
- Parameter is moved into a struct or collection
- Trait implementation with fixed signature
- `Box<dyn Trait>` (ownership is idiomatic for trait objects)

**Template:**
```
SUGGESTION: Pass by reference (suggest)

Parameter `X: String` at line N is only read. Consider `X: &str` to avoid
unnecessary cloning at call sites.

CAVEAT: If called from async contexts needing 'static bounds, ownership
may be required. Verify with `cargo check`.
```

---

### 5. Type Alias for Repeated Complex Types

**Confidence:** `auto-apply`

**Preconditions:**
- Same generic type signature appears 3+ times in the file/module
- Not a framework-constrained type (e.g., Pingora trait types)

**Contraindications:**
- Type appears only in trait bounds (aliasing bounds is non-idiomatic)
- Already an alias
- Only in test code

**Template:**
```
SUGGESTION: Introduce type alias (auto-apply)

`Arc<RwLock<HashMap<K, V>>>` appears N times. Consider:
  type SharedMap = Arc<RwLock<HashMap<K, V>>>;

Reduces visual noise and creates a single point of change.
```

---

## Judgment-Required (4 techniques)

### 6. Extract Function

**Confidence:** `flag-for-review`

**Preconditions:**
- A contiguous block of 20+ lines with:
  - Clear single responsibility (identifiable by a comment or paragraph break)
  - Uses <= 3 variables from the enclosing scope
  - Produces a single output

**Contraindications:**
- Block contains `unsafe` or sits between unsafe and its invariant-restoring code
- Block crosses an `.await` boundary AND captures non-Send types
- Block uses `&'static self` (propagation is non-obvious)
- **Shallow module brake**: `param_count + return_fields >= body_lines / 3`
- **Single call-site + high coupling**: only called from 1 place AND >3 params
- **Zero intention gap**: body is only stdlib calls (name adds nothing)

**Template:**
```
SUGGESTION: Extract function (flag-for-review)

Lines N-M (<purpose>) could be extracted:
  - Uses K variables from enclosing scope
  - Produces: <output description>
  - Unsafe: none / PRESENT (manual review required)
  - Async boundaries: none / PRESENT (Send bound warning)

Proposed: fn <name>(<params>) -> <return>

OVER-ABSTRACTION CHECK:
  Interface: K params + M return fields = J
  Body: L lines
  Ratio: J/L = X (threshold: 0.33)
  Result: PASS / WARN: extraction may increase net complexity

CAUTION: Verify the extraction improves readability for someone unfamiliar
with this module. If the name would be "do_the_next_thing", skip it.
```

---

### 7. `?` Operator Replacement

**Confidence:** `suggest`

**Preconditions:**
- Match on Result/Option where Err/None arm returns early with the error
- Ok/Some arm extracts the value and continues

**Contraindications:**
- Err arm has side effects (circuit breaker signaling, metrics, logging with context)
- Err arm handles specific error types differently (e.g., ESTALE vs EIO)
- Match is on a domain type where `?` would lose error discrimination

**Template:**
```
SUGGESTION: Replace match with ? (suggest)

The match at line N extracts Ok(val) and returns on Err with no side effects.
Simplify to: let val = expression?;

NOTE: Verify the Err arm has no side effects. NFS error handling in this
codebase often includes ESTALE detection and circuit breaker signaling
that would be lost with `?`.
```

---

### 8. Merge Match Arms

**Confidence:** `suggest`

**Preconditions:**
- Two+ match arms with identical bodies
- Patterns combinable with `|`

**Contraindications:**
- Arms are intentionally separate for future divergence (check for TODO comments)
- Arms represent semantically distinct domain concepts even with same current handling
- Match is on an error type where each variant has distinct operational meaning

**Template:**
```
SUGGESTION: Merge match arms (suggest)

Arms at lines N and M have identical bodies. Consider:
  Pattern1 | Pattern2 => { ... }

NOTE: Only merge if identical handling is intentional and permanent. If
these may diverge, separate arms are better documentation.
```

---

### 9. `let-else` Replacement

**Confidence:** `suggest`

**Preconditions:**
- `if let Some(x) = expr { ... long body ... } else { return/continue; }`
- Happy path body is > 5 lines
- Else branch is a simple divergence (return, continue, break)

**Contraindications:**
- Else branch has multi-statement logic (metrics, logging, state transitions)
- Else branch exceeds 3 lines

**Template:**
```
SUGGESTION: Replace if-let with let-else (suggest)

Rewrite at line N:
  let Some(x) = expr else { return; };
  // ... happy path at reduced nesting ...

Reduces nesting by 1 level for N lines.

NOTE: Only appropriate when the else is a simple divergence. Keep if-let
when the else has logging, metrics, or cleanup.
```

---

## Not Automatable (3 techniques)

### 10. Collapse If-Chains

**Confidence:** `flag-for-review`

**Preconditions:**
- Sequential if-checks testing related conditions
- Could theoretically combine with `&&` or restructure as match

**Contraindications:**
- Each if has side effects between checks (logging, metrics, state)
- Chain is a documented pipeline with per-step purpose comments
- Steps have data dependencies where intermediate results are used later

**Template:**
```
FLAG: Sequential if-chain (flag-for-review)

Lines N-M contain K sequential if-checks. This may be:
(a) A pipeline with essential sequential coupling -- leave as-is
(b) Redundant checks that could be consolidated

Review purpose of each check. Only consolidate if all checks are pure
preconditions with no intermediate side effects.
```

---

### 11. Replace Conditional with Polymorphism

**Confidence:** `flag-for-review`

**Preconditions:**
- Large match/if-else dispatching on a type/variant with >20 lines per arm
- Same dispatch pattern appears in multiple functions

**Contraindications:**
- Dispatch is on runtime data, not type variants
- Framework constrains the trait hierarchy
- Only one function has this pattern (polymorphism for a single dispatch is over-engineering)

**Template:**
```
FLAG: Repeated type dispatch (flag-for-review)

The dispatch at line N on <type> with K arms (>20 lines each) appears
in N locations. This MAY suit a trait-based design, but requires evaluating:
  1. Whether the dispatch pattern is stable
  2. Whether variants share sufficient interface
  3. Whether framework constraints allow it

This skill does not make this recommendation automatically.
```

---

### 12. Decompose State Machine

**Confidence:** `flag-for-review`

**Preconditions:**
- Function > 200 LOC with sequential stages separated by error handling
- Multiple match expressions on intermediate results
- Name or comments indicate multi-step process

**Contraindications:**
- Stages have essential sequential coupling (each depends on previous output)
- Error handling is distinct and stage-specific
- Function handles NFS/IO where scattering recovery narrative harms incident response

**Template:**
```
FLAG: Multi-stage sequential function (flag-for-review)

K identifiable stages over N lines, each with stage-specific error handling.

Sequential state machines (create -> write -> fsync -> rename) intentionally
keep all stages visible in one function so the full error recovery narrative
is readable in one place. Decomposition scatters this across K functions.

Consider decomposition ONLY if:
  - Stages are independently testable
  - Error handling is uniform across stages
  - Function exceeds 400 LOC AND has accidental complexity beyond the
    sequential structure itself
```
