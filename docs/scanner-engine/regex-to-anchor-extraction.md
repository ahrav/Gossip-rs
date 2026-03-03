# Regex-to-Anchor Extraction

## Overview

The `regex2anchor` module (`crates/scanner-engine/src/regex2anchor.rs`) extracts literal byte substrings ("anchors") from regex patterns for use as Vectorscan prefilters. This enables a two-pass scanning architecture:

1. **Fast pass**: Vectorscan scans the haystack for anchor literals (hardware-accelerated multi-pattern matching).
2. **Slow pass**: The full regex engine runs only on candidate regions where an anchor was found.

Without anchors, every regex rule must run against the entire input. With anchors, the engine skips regions that cannot possibly match, producing large throughput gains on real-world workloads where most of the input does not contain secrets.

### Why This Matters

Anchor extraction is the critical bridge between regex rules (authored by humans for readability) and Vectorscan databases (optimized for throughput). A pattern like `ghp_[A-Za-z0-9]{36}` compiles to the anchor `"ghp_"`, so Vectorscan only reports positions containing that 4-byte literal. The full regex then confirms the trailing 36-character alphanumeric suffix in a narrow window.

## Soundness Invariant

The single non-negotiable correctness rule:

```
For any pattern P and haystack H:
  if regex_matches(P, H),
  then H must contain at least one derived anchor.
```

If this invariant is violated, the scanner produces **false negatives** (missed secrets). The algorithm is therefore conservative: it returns errors (`Unanchorable`, `OnlyWeakAnchors`) when it cannot safely produce anchors, rather than risk missing a match.

Key corollaries:

- Patterns that can match the empty string are **always** rejected (`regex2anchor.rs:1446-1452`). An empty match has no bytes for an anchor to match against.
- Anchors are never filtered by length post-derivation for alternations. If an alternation branch produces a short anchor, the entire set is rejected as `OnlyWeakAnchors` rather than silently dropping the short branch (`regex2anchor.rs:1310-1311`).
- Information is only ever **weakened**, never strengthened, as it propagates up the HIR tree (`regex2anchor.rs:506`).

## Algorithm

### High-Level Pipeline

```
Regex string
    │
    ▼
┌────────────────────────────────┐
│  Parse via regex-syntax        │
│  ParserBuilder → HIR           │
│  (handles flags, case folding) │
└────────────┬───────────────────┘
             │
             ▼
┌────────────────────────────────┐
│  analyze(hir, cfg)             │
│  Structural induction on HIR   │
│  Returns Info { exact, pf }    │
└────────────┬───────────────────┘
             │
             ▼
┌────────────────────────────────┐
│  choose_anchors(info, cfg)     │
│  Enforce min_anchor_len        │
│  Reject empty-matching sets    │
└────────────┬───────────────────┘
             │
             ▼
┌────────────────────────────────┐
│  TriggerPlan                   │
│  Anchored / Residue /          │
│  Unfilterable                  │
└────────────────────────────────┘
```

### Step 1: Parse to HIR

The module uses `regex-syntax::ParserBuilder` to parse the pattern into a High-level Intermediate Representation (HIR). The `AnchorDeriveConfig::utf8` flag controls whether UTF-8 or byte-oriented parsing is used — this must match the regex engine that will perform the final match (`regex2anchor.rs:1439-1444`).

HIR handles flags (`(?i)`, `(?-u)`), case folding, and character class normalization. For example, `(?i:ab)` is lowered to `[aA][bB]`, which the analyzer handles as two character classes without needing case folding logic.

### Step 2: Analyze the HIR

The `analyze` function (`regex2anchor.rs:512-550`) performs structural induction on each HIR node, returning an `Info` value that tracks:

- **`exact`**: An explicit, finite set of byte strings the node can match (or `None` if the set is too large or unbounded).
- **`pf`**: A `Prefilter` summary (a required substring or set of substrings) that must appear in any match.

Each HIR node type has specific analysis rules:

| HIR Node | Analysis Rule | Reference |
|---|---|---|
| `Empty` | Exact set `{b""}` | `regex2anchor.rs:514-517` |
| `Literal(bytes)` | Exact singleton `{bytes}` | `regex2anchor.rs:519-521` |
| `Class` | Expand to exact set if small ASCII/byte; otherwise `All` | `regex2anchor.rs:524-531` |
| `Look` | Treated as empty (zero-width; consumes no bytes) | `regex2anchor.rs:534-536` |
| `Repetition` | Delegated to `analyze_repetition` | `regex2anchor.rs:539` |
| `Capture` | Transparent; analyze inner sub-expression | `regex2anchor.rs:541-543` |
| `Concat` | Delegated to `analyze_concat` | `regex2anchor.rs:546` |
| `Alternation` | Delegated to `analyze_alternation` | `regex2anchor.rs:548` |

### Step 3: Combine Child Info

**Concatenation** (`analyze_concat`, `regex2anchor.rs:801-856`):

1. Try full cross-product of all children's exact sets. If the result fits within config caps, return the exact set.
2. Otherwise, find the best **contiguous exact window** via `best_exact_window_prefilter` — this searches every contiguous run of children with exact sets, cross-products them, and picks the highest-scoring window (`regex2anchor.rs:714-787`).
3. Fall back to the single most selective child prefilter.

**Alternation** (`analyze_alternation`, `regex2anchor.rs:867-926`):

1. If all branches have exact sets, union them into one exact set.
2. Otherwise, collect all branch anchors into an `AnyOf` set. If any branch is `All` (unanchorable) or can match the empty string, the entire alternation degrades to `All`.

**Repetition** (`analyze_repetition`, `regex2anchor.rs:560-621`):

- `min == 0`: Required substrings may disappear. Special cases: `{0}` returns exact `{b""}`, and `?` (max=1) returns `{b""} ∪ sub_exact`. Otherwise degrades to `All`.
- `min > 0`: Cross-product the sub's exact set `min` times. For exact repetition (`max == min`), the result stays exact. For open-ended repetition, the mandatory `min` copies produce a prefilter.

### Step 4: Choose Anchors and Build Trigger Plan

`choose_anchors` (`regex2anchor.rs:1297-1343`) enforces global constraints on the final `Info`:

- Empty strings in the exact set yield `Unanchorable`.
- Any anchor shorter than `min_anchor_len` yields `OnlyWeakAnchors` (no partial filtering — that would be unsound).
- Empty `AnyOf` sets yield `Unanchorable`.

`compile_trigger_plan` (`regex2anchor.rs:1435-1491`) orchestrates the full pipeline:

1. Reject empty-matching patterns upfront.
2. Attempt anchor derivation (fastest gate).
3. If anchors fail, attempt a residue gate (run-length or k-gram).
4. If all fail, return `Unfilterable` with the reason.

## Key Types

### `AnchorDeriveConfig` (`regex2anchor.rs:81-111`)

Configuration controlling all derivation limits:

| Field | Default | Purpose |
|---|---|---|
| `min_anchor_len` | 3 | Minimum anchor byte length; shorter anchors are rejected |
| `max_exact_set` | 64 | Maximum elements in an exact set before degrading |
| `max_exact_string_len` | 256 | Maximum byte length of any single exact string |
| `max_class_expansion` | 16 | Maximum character class expansion size |
| `utf8` | true | Whether to parse with UTF-8 semantics |
| `kgram_k` | 4 | K-gram prefix length (feature-gated) |
| `max_kgram_set` | 4096 | Maximum k-gram enumeration count (feature-gated) |
| `max_kgram_alphabet` | 32 | Maximum per-position alphabet for k-grams (feature-gated) |

### `Info` (`regex2anchor.rs:294-300`)

Internal per-node summary. Not public — used only during HIR traversal:

- `exact: Option<Vec<Vec<u8>>>` — Finite set of byte strings the node can match, or `None`.
- `pf: Prefilter` — A prefilter summary preserved when `exact` is unavailable.

### `Prefilter` (`regex2anchor.rs:152-160`)

```rust
pub enum Prefilter {
    All,                    // No useful anchor; matches too broadly
    AnyOf(Vec<Vec<u8>>),    // Any of these substrings must be present
    Substring(Vec<u8>),     // This specific substring must be present
}
```

### `TriggerPlan` (`regex2anchor.rs:173-188`)

The output of `compile_trigger_plan`:

- **`Anchored { anchors, confirm_all }`** — At least one anchor must appear in any match. `confirm_all` is an optional AND filter of mandatory literal islands used to reduce false positives after an anchor hit.
- **`Residue { gate }`** — Conservative ASCII-only gate (run-length or k-gram) when anchors are unavailable.
- **`Unfilterable { reason }`** — No safe gate exists; caller must run the full regex.

### `AnchorDeriveError` (`regex2anchor.rs:137-144`)

```rust
pub enum AnchorDeriveError {
    InvalidPattern(String),   // Regex failed to parse
    Unanchorable,             // Pattern matches too broadly (e.g., `.*`)
    OnlyWeakAnchors,          // All anchors shorter than min_anchor_len
}
```

### `ResidueGatePlan` (`regex2anchor.rs:212-220`)

Fallback gate when anchors are unavailable:

- **`RunLength(RunLengthGate)`** — Scan for a byte-class run of `[min_len, max_len]` bytes. Only applies to patterns that reduce to a single consuming ASCII atom.
- **`KGrams(KGramGate)`** — Enumerated prefix k-grams (feature-gated via `kgram-gate`).
- **`Or(Vec<ResidueGatePlan>)`** — Logical OR for alternations.

### `RunLengthGate` (`regex2anchor.rs:244-260`)

A 256-bit byte mask with min/max run length, optional ASCII word boundary, and optional UTF-16 variant scanning.

### `KGramGate` (`regex2anchor.rs:267-274`)

K-length prefix grams packed as `u64` values (little-endian for k <= 8, FNV-1a hash for k > 8). Feature-gated behind `kgram-gate`.

## Supported Regex Patterns

### Fully Handled

| Construct | Example | Anchor Result |
|---|---|---|
| Literal | `foo` | `["foo"]` |
| Concatenation | `foobar` | `["foobar"]` |
| Alternation | `foo\|bar` | `["foo", "bar"]` |
| Small character class | `[ab]cd` | `["acd", "bcd"]` |
| Exact repetition | `a{3}` | `["aaa"]` |
| Bounded repetition (min>0) | `a{2,4}` | `["aa"]` (minimum copies) |
| Plus repetition | `a{3,}` | `["aaa"]` (minimum copies) |
| Optional (`?`) with exact sub | `a?` (in concat context) | Exact `{b"", b"a"}` |
| Capture groups | `(foo)(bar)` | `["foobar"]` (transparent) |
| Anchors (`^`, `$`) | `^foo$` | `["foo"]` (zero-width) |
| Word boundaries | `\bfoo\b` | `["foo"]` (zero-width) |
| Case-insensitive flag | `(?i:ab)` | `["AB", "Ab", "aB", "ab"]` (via HIR lowering) |
| Non-ASCII literals | `日本` | `[UTF-8 bytes of "日本"]` |
| Byte-mode hex | `(?-u)\xFF` (with `utf8=false`) | `[b"\xFF"]` |
| Nested alternation | `(a\|b)\|(c\|d)` | `["a", "b", "c", "d"]` |
| Overlapping alternatives | `foo\|foobar` | `["foo", "foobar"]` |

### Degraded to Broader Prefilter or Residue Gate

| Construct | Example | Behavior |
|---|---|---|
| Large character class | `[a-z]` (>16 elements) | Class degrades to `All`; may still extract anchor from surrounding concat context |
| Hex character class | `[A-F0-9]{4}` | Run-length gate (4 bytes of hex mask) |
| Dot (any char) | `.` | `All` (too broad) |
| Star repetition (min=0) | `a*` | `All` (can match empty) |
| Unicode character class | `\p{L}` | `All` (non-ASCII expansion rejected) |

### Rejected as Unfilterable

| Construct | Example | Reason |
|---|---|---|
| Empty-matching patterns | `a*`, `a?`, `\|a` | `MatchesEmptyString` |
| Pure wildcard | `.*` | `Unanchorable` |
| Mixed-length alternation with short branch | `ab\|abcdef` (min=3) | `OnlyWeakAnchors` |
| All-wildcard alternation branch | `.*\|foo` | `Unanchorable` (one branch is `All`) |

## Edge Cases

### Optional Groups in Concatenation

Pattern `a?bcd` with `min_anchor_len=3`:

- `a?` is analyzed as `{b"", b"a"}` (exact set with empty).
- The concatenation cross-product with `bcd` yields `{b"bcd", b"abcd"}`.
- The exact window search finds the best window. If the full cross-product exceeds caps, the algorithm falls back to the best contiguous exact window, which still includes `b"bcd"`.

### Nested Alternations

Pattern `((a|b)|(c|d))` with `min_anchor_len=1`:

- Inner alternations produce exact sets `{a, b}` and `{c, d}`.
- The outer alternation unions them: `{a, b, c, d}`.
- All branches have anchors, so the result is sound.

### Alternation with Empty Branch

Pattern `foo|` or `|foo`:

- The empty branch makes the pattern match the empty string.
- `hir_matches_empty` returns true, so `compile_trigger_plan` returns `Unfilterable { reason: MatchesEmptyString }` before anchor derivation is attempted.
- `derive_anchors_from_pattern` also catches this: the exact set contains `b""`, which triggers `Unanchorable`.

### Case-Insensitive Patterns

Pattern `(?i)foo`:

- HIR lowering converts this to `[fF][oO][oO]`.
- Character class expansion produces 2 options per position.
- Cross-product yields 2^3 = 8 anchors: `["FOO", "FOo", "FoO", "Foo", "fOO", "fOo", "foO", "foo"]`.

### Exact Window Selection in Concatenation

Pattern `"api" [_-] "key" "=" [0-9]+`:

The algorithm searches every contiguous window of exact children, computes the cross-product for each window, and selects the best by a scoring heuristic. The detailed example in the code (`regex2anchor.rs:674-712`) shows how `["api_key=", "api-key="]` (score 63) beats the single-child fallback of `"api"` or `"key"` (score 24).

### Repetition with Character Classes

Pattern `[ab]{2}` with `min_anchor_len=2`:

- `[ab]` expands to exact set `{b"a", b"b"}`.
- `{2}` cross-products twice: `{b"aa", b"ab", b"ba", b"bb"}`.
- All 4 anchors are returned.

### Cross-Product Overflow

Pattern `[abc][def][ghi]` with `max_exact_set=64`:

- Each class has 3 elements: 3 * 3 * 3 = 27 combinations.
- 27 <= 64, so the full cross-product succeeds.
- If the product exceeds `max_exact_set`, the algorithm falls back to the best window or child prefilter.

### confirm_all Literal Islands

Pattern `foo\d+bar`:

- `compile_trigger_plan` extracts anchors (e.g., `"foo"` or `"bar"`) and then calls `collect_confirm_all_literals` to find mandatory fixed-literal islands from the top-level concatenation.
- Both `"foo"` and `"bar"` are mandatory islands. The one chosen as the primary anchor is excluded from `confirm_all`; the other is kept as an AND filter to reduce false positive candidate windows (`regex2anchor.rs:1459-1460`).

## Integration: From Anchors to Vectorscan

Anchors flow from `regex2anchor` into the engine via `core.rs`:

1. **Rule compilation** (`core.rs:615`): `compile_trigger_plan(rule.re, &derive_cfg)` is called for each rule.

2. **Anchor registration** (`core.rs:630-673`): For `TriggerPlan::Anchored`, each anchor is registered as:
   - A raw-byte pattern (Variant::Raw)
   - A UTF-16LE encoded pattern (Variant::Utf16Le)
   - A UTF-16BE encoded pattern (Variant::Utf16Be)

3. **Database compilation** (`vectorscan_prefilter.rs`): Anchor byte sequences are encoded as `\xNN` Vectorscan patterns and compiled into block-mode or stream-mode databases alongside raw rule patterns.

4. **Runtime scanning**: Vectorscan reports anchor hits via callbacks. Each hit seeds a candidate window using the anchor's position plus configurable seed radius. Only these windows are passed to the full regex engine.

5. **Residue/Unfilterable handling** (`core.rs:675-691`): Rules with `Residue` or `Unfilterable` plans fall back to manual anchor patterns (if provided by the rule author) or are flagged as unfilterable.

```
┌──────────────┐    ┌──────────────────┐    ┌───────────────────┐
│ Rule spec    │───▶│ compile_trigger   │───▶│ TriggerPlan       │
│ (regex str)  │    │ _plan()           │    │                   │
└──────────────┘    └──────────────────┘    └─────────┬─────────┘
                                                      │
                    ┌─────────────────────────────────┐│┌──────────────────────┐
                    │         Anchored                 │││    Unfilterable      │
                    ▼                                  │▼│                      ▼
         ┌───────────────────┐                   ┌─────┴──────┐    ┌──────────────────┐
         │ Register anchors  │                   │ Residue    │    │ Fall back to     │
         │ Raw + UTF16LE/BE  │                   │ gate plan  │    │ manual anchors   │
         │ into pat_map      │                   └────────────┘    │ or skip prefilter│
         └────────┬──────────┘                                     └──────────────────┘
                  │
                  ▼
         ┌───────────────────┐
         │ VsPrefilterDb     │
         │ compile patterns  │
         │ into Vectorscan   │
         └────────┬──────────┘
                  │
                  ▼
         ┌───────────────────┐
         │ Runtime: scan     │
         │ haystack, seed    │
         │ candidate windows │
         └───────────────────┘
```

## Scoring Heuristic

When multiple anchor candidates exist (e.g., in concatenation), the algorithm selects the most selective option using a scoring heuristic (`regex2anchor.rs:654-657`):

```
score = min_len * 8 - ceil_log2(set_size)
```

- Longer anchors score higher (8 bits of "selectivity" per byte).
- Large `AnyOf` sets incur a log2 penalty.
- Example: min_len=4, set_size=16 → score = 32 - 4 = 28.
- This favors a small set of longer anchors over a large set of short ones.

Tie-breaking (`regex2anchor.rs:768-770`): when scores are equal, prefer higher `min_len`, then fewer set elements, then higher `max_len`.

## Residue Gates

When anchors are unavailable, the algorithm attempts conservative fallback gates:

### Run-Length Gate (`regex2anchor.rs:979-1022`)

Applies to patterns that reduce to a single consuming ASCII atom (literal or class) with optional repetition and word boundaries. The gate specifies:

- A 256-bit byte mask of allowed bytes
- Min/max run length in bytes
- Optional ASCII word boundary requirement (only when both leading and trailing boundaries are present)
- Optional UTF-16 variant scanning

Example: `[A-F0-9]{4}` → RunLengthGate with hex byte mask, min=4, max=4.

### K-Gram Gate (`regex2anchor.rs:1092-1163`, feature-gated)

Enumerates all possible k-length prefixes of the pattern. Each position contributes an ASCII alphabet; the cross-product of alphabets produces k-gram hashes stored for fast membership checking. Only applies when the prefix is fixed-length and enumerable.

### Alternation Residue (`regex2anchor.rs:954-964`)

For alternations where individual branches have residue gates, an `Or(Vec<ResidueGatePlan>)` is produced. All branch gates must exist; if any branch has no gate, the entire plan fails.

## Testing

### Unit Tests (`regex2anchor_tests.rs`)

756 lines of targeted tests covering:

- Basic functionality: literals, concatenation, alternation, repetition, character classes (`regex2anchor_tests.rs:44-212`)
- Bug-hunting tests for specific failure modes: min-anchor-length post-filtering, optional prefix handling, cross-product overflow, empty alternation branches, Unicode vs. bytes (`regex2anchor_tests.rs:218-486`)
- Property-based tests using proptest with correlated pattern/haystack pairs (`regex2anchor_tests.rs:492-633`)
- Real-world pattern tests: AWS access keys, GitHub tokens, JWTs, Slack tokens (`regex2anchor_tests.rs:670-756`)

### Soundness Property Tests (`regex2anchor_soundness.rs`)

1,068 lines of exhaustive and property-based soundness verification:

- **Exhaustive domain tests** (`regex2anchor_soundness.rs:284-338`): Enumerate all strings of length 0..6 over alphabet `{a,b,c,d}` (5,461 strings). For each pattern, verify that every regex match contains at least one anchor.
- **Property-based tests** (`regex2anchor_soundness.rs:436-590`): 250-500 cases with simple and complex generated patterns, tested against exhaustive small domains and random byte haystacks.
- **Metamorphic tests** (`regex2anchor_soundness.rs:490-543`): Verify that wrapping a pattern in a capture group does not change the derived anchors.
- **Edge case tests**: nested alternations, repetition bounds, concatenation with classes, case-insensitive flags, byte-mode hex escapes, NUL bytes, class expansion limits, exact set size limits.
- **TriggerPlan tests** (`regex2anchor_soundness.rs:916-1068`): Verify that `compile_trigger_plan` produces the correct plan type (Anchored, Residue, Unfilterable) for various patterns, including run-length gates, OR gates for alternations, and k-gram gates (feature-gated).

### Verification Approach

The soundness tests implement the invariant check directly:

```rust
// For every haystack in the domain:
if regex.is_match(&haystack) && !anchors_cover_match(&haystack, &anchors) {
    // Soundness violation found — this is a bug
}
```

This provides a mathematical proof of correctness over the bounded domain and statistical confidence via property-based testing over larger inputs.

## Source of Truth

| Component | File | Lines |
|---|---|---|
| Module implementation | `crates/scanner-engine/src/regex2anchor.rs` | 1-1556 |
| `AnchorDeriveConfig` | `crates/scanner-engine/src/regex2anchor.rs` | 81-126 |
| `AnchorDeriveError` | `crates/scanner-engine/src/regex2anchor.rs` | 137-144 |
| `Prefilter` enum | `crates/scanner-engine/src/regex2anchor.rs` | 152-160 |
| `TriggerPlan` enum | `crates/scanner-engine/src/regex2anchor.rs` | 173-188 |
| `UnfilterableReason` | `crates/scanner-engine/src/regex2anchor.rs` | 196-205 |
| `ResidueGatePlan` / `RunLengthGate` / `KGramGate` | `crates/scanner-engine/src/regex2anchor.rs` | 212-285 |
| `Info` (internal) | `crates/scanner-engine/src/regex2anchor.rs` | 294-332 |
| `class_to_small_byte_set` | `crates/scanner-engine/src/regex2anchor.rs` | 343-372 |
| `cross_product` | `crates/scanner-engine/src/regex2anchor.rs` | 479-499 |
| `analyze` (core HIR dispatch) | `crates/scanner-engine/src/regex2anchor.rs` | 512-550 |
| `analyze_repetition` | `crates/scanner-engine/src/regex2anchor.rs` | 560-621 |
| `best_exact_window_prefilter` | `crates/scanner-engine/src/regex2anchor.rs` | 714-787 |
| `analyze_concat` | `crates/scanner-engine/src/regex2anchor.rs` | 801-856 |
| `analyze_alternation` | `crates/scanner-engine/src/regex2anchor.rs` | 867-926 |
| `derive_residue_gate_plan` | `crates/scanner-engine/src/regex2anchor.rs` | 951-968 |
| `derive_run_length_gate` | `crates/scanner-engine/src/regex2anchor.rs` | 979-1022 |
| `extract_core_with_boundary` | `crates/scanner-engine/src/regex2anchor.rs` | 1033-1081 |
| `derive_kgram_gate` (feature-gated) | `crates/scanner-engine/src/regex2anchor.rs` | 1092-1163 |
| `choose_anchors` | `crates/scanner-engine/src/regex2anchor.rs` | 1297-1343 |
| `collect_confirm_all_literals` | `crates/scanner-engine/src/regex2anchor.rs` | 1364-1419 |
| `compile_trigger_plan` (public entry) | `crates/scanner-engine/src/regex2anchor.rs` | 1435-1491 |
| `derive_anchors_from_pattern` (public entry) | `crates/scanner-engine/src/regex2anchor.rs` | 1513-1528 |
| Engine integration (caller) | `crates/scanner-engine/src/engine/core.rs` | 615-692 |
| Vectorscan prefilter module | `crates/scanner-engine/src/engine/vectorscan_prefilter.rs` | — |
| Unit tests | `crates/scanner-engine/src/regex2anchor_tests.rs` | 1-756 |
| Soundness property tests | `crates/scanner-engine-integration-tests/tests/property/regex2anchor_soundness.rs` | 1-1068 |
