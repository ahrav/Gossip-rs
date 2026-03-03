# Engine Window Validation Module

**File**: `crates/scanner-engine/src/engine/window_validate.rs`

## Module Purpose

The window validation module executes compiled detection rules against bounded byte windows extracted from scanned data. It performs the critical "hot path" validation where patterns are matched, gates are enforced, and findings are recorded. The module handles both raw binary data and UTF-16 encoded content, applying progressive filtering through cheap gates before expensive regex matching.

Global safelist suppression for root emit paths and offline structural
validation (CRC, charset, etc.) for root-semantic findings are both enforced
inline at finding emission time in this module.

Two entry styles are supported:
- **Engine hot path**: `run_rule_on_window` writes findings directly into `ScanScratch` and performs dedupe bookkeeping immediately.
- **Scheduler adapters**: `run_rule_on_raw_window_into` / `run_rule_on_utf16_window_into` accumulate findings into scratch staging buffers so the caller can commit results and track drops.

### Key Responsibilities

- **Gate-based filtering**: Apply cost-effective byte-level checks before regex execution
- **Coordinate space management**: Maintain separate coordinate systems for raw bytes, UTF-16 variants, and decoded UTF-8 output
- **Budget enforcement**: Track and limit UTF-16 decoding resource consumption
- **Finding extraction**: Record matches with proper span information and secret data extraction
- **Entropy validation**: Gate findings on Shannon entropy and optional min-entropy (NIST SP 800-90B) of extracted secret bytes
- **Value suppression**: Discard findings whose extracted secret contains known placeholder/example patterns
- **Emit-time policy checks**: Apply root safelist suppression and offline structural validation before recording findings
- **Confidence thresholding**: Suppress candidates whose computed confidence score is below per-rule `min_confidence`

---

## Window Building Algorithm

Windows are provided externally (typically from anchor hits detected by Vectorscan) and represent bounded byte ranges within a buffer. The module does not build windows but validates them according to this pattern:

```
Input: Window [w.start..w.end) in buffer
  ↓
[Gate 1] Apply cheap byte gates (must-contain, confirm-all, keywords for Raw)
  ↓
[Gate 2] For UTF-16: Check decode budget + decode to UTF-8 + must-contain
  ↓
[Gate 3] Apply assignment-shape precheck (if rule-specific)
  ↓
[Gate 4] Apply character-class distribution gate (SIMD-accelerated, when configured)
  ↓
[Gate 5] Run regex with capture groups
  ↓
[Gate 6] Extract secret span from capture groups
  ↓
[Gate 7] Check entropy on extracted secret (Shannon + optional digit penalty + optional min-entropy)
  ↓
[Step 8] Probe for keyword evidence in local context (±32 bytes around full match)
  ↓
[Gate 9] Apply value suppressors on extracted secret bytes (when configured)
  ↓
[Gate 10] Apply local context checks (bounded, fail-open)
  ↓
[Gate 11] Apply root-context safelist suppression (emit-time, `step_id == STEP_ROOT` findings only)
  ↓
[Gate 12] Apply secret-bytes safelist suppression (all findings, including decoded)
  ↓
[Gate 13] Apply UUID-format quick-reject (all findings, gated per-rule by uuid_format_secret())
  ↓
[Gate 14] Apply offline structural validation (CRC, charset, etc.) for root-semantic findings
  ↓
[Step 15] Compute additive confidence score from per-finding evidence outcomes
  ↓
[Gate 16] Apply per-rule `min_confidence` threshold
  ↓
Output: FindingRec with spans in appropriate coordinate space
```

### Anchor Hint Processing

The `anchor_hint` parameter indicates where Vectorscan detected a match start. The validator applies a **back-scan margin** (`BACK_SCAN_MARGIN = 64` bytes) to allow patterns that may have backward context:

```rust
let hint_in_window = anchor_hint.saturating_sub(w.start);
let search_start = hint_in_window.saturating_sub(BACK_SCAN_MARGIN);
let search_window = &window[search_start..];
```

This margin accounts for patterns where the anchor may appear in the middle of the full regex match (e.g., the `ghp_` anchor in `([A-Za-z_]+\s*=\s*)(ghp_[A-Za-z0-9]{36})`).

---

## Merge and Coalesce Strategies

This module does not implement merge or coalesce operations. Those are handled in separate modules (e.g., window build/merge stages). The window validation module receives pre-built windows (which may overlap) and focuses only on validation and finding extraction.

---

## run_rule_on_window: The Hot Path Validation Function

```rust
pub(super) fn run_rule_on_window(
    &self,
    rule_id: u32,
    rule: &RuleCompiled,
    variant: Variant,
    buf: &[u8],
    w: Range<usize>,
    step_id: StepId,
    root_hint: Option<Range<usize>>,
    base_offset: u64,
    file_id: FileId,
    scratch: &mut ScanScratch,
    anchor_hint: usize,
    gates: &ResolvedGates<'_>,
)
```

This is the primary entry point for window validation. It:

1. Extracts the window slice from the buffer
2. Routes to variant-specific logic (Raw, UTF-16LE, UTF-16BE)
3. Runs all gates in sequence
4. Executes regex matching
5. Records findings into scratch space

### Coordinate Space Handling

The function maintains invariants about coordinate spaces:

- **Raw variant**: All spans are expressed in raw buffer byte offsets
- **UTF-16 variants**:
  - Spans in findings are in decoded UTF-8 byte space
  - Root hints use the **full match span** mapped back to raw UTF-16 byte offsets, and then (when available) through `root_span_map_ctx`
  - A `DecodeStep::Utf16Window` is attached to findings to enable mapping back to parent raw offsets

### Return Behavior

Early returns occur when:
- Any gate fails (must-contain, confirm-all, keywords, assignment-shape)
- Decode budget is exhausted (UTF-16 variants)
- Decoding fails (UTF-16 variants)
- Regex produces no matches

Late returns occur when:
- Entropy gates reject a match (continues to next match, not full return)

---

## Gate Checks

Gates are applied in strict sequence. Each gate is a cheap byte-level check that eliminates impossible windows before expensive regex execution.

### 1. must_contain Gate

```rust
if let Some(needle) = rule.must_contain {
    if memmem::find(window, needle).is_none() {
        return;
    }
}
```

**Purpose**: Reject windows that lack a required literal byte sequence.

**Performance**: O(window.len()) byte search using `memchr::memmem`

**Use case**: High-confidence anchor literal that must appear for any regex match to be possible.

### 2. confirm_all Gate

```rust
if let Some(confirm) = self.confirm_all_gate(rule.confirm_all) {
    let vidx = Variant::Raw.idx();
    if let Some(primary) = &confirm.primary[vidx] {
        if memmem::find(window, primary).is_none() {
            return;
        }
    }
    if !contains_all_memmem(window, &confirm.rest[vidx]) {
        return;
    }
}
```

**Purpose**: Require all specified literal byte sequences to be present in the window.

**Components**:
- `primary`: Main required literal (fast-path)
- `rest`: Additional required literals that must all be found

**Performance**: Early exit on first missing literal; typically O(window.len()) total.

**Use case**: Context validation (e.g., "window must contain 'secret' AND 'key' AND 'password'")

### 3. keywords_any Gate

```rust
if let Some(kws) = self.keyword_gate(rule.keywords) {
    if !contains_any_memmem(window, &kws.any[Variant::Raw.idx()]) {
        return;
    }
}
```

**Purpose**: Cheap pre-regex filter: window must contain at least one of the specified keyword literals.

**Performance**: Returns on first match found; efficient early exit.

**Variant handling**:
- Raw variant: Check against raw window directly
- UTF-16 variants: Check against raw UTF-16 bytes *before* decoding to avoid wasting decode budget

**Use case**: Eliminate windows that could never match the rule's regex regardless of structure.

### 4. Assignment-Shape Precheck

```rust
if rule.needs_assignment_shape_check() && !has_assignment_value_shape(window) {
    return;
}
```

**Purpose**: Reject windows that lack the basic structure for assignment patterns (e.g., `key=value`).

**When enabled**: When the rule regex expects an assignment-like structure.

### 5. Character-Class Distribution Gate

```rust
if let Some(cc) = gates.char_class {
    if !char_class_gate_passes(window, cc) {
        return;
    }
}
```

**Purpose**: Reject windows dominated by lowercase ASCII (prose, variable names) that cannot be high-entropy secrets.

**Algorithm**: SIMD-accelerated byte classification (NEON on aarch64, SSE2 on x86_64) counts lowercase/uppercase/digit/special bytes. If `lower_count * 100 > total * max_lower_pct`, the window is rejected. Integer cross-multiply avoids float division on the hot path.

**Fail-open**: Windows shorter than `min_window_len` pass unconditionally. This is intentional: the char_class gate is a false-positive filter, not a security boundary. Failing open on short windows prevents suppressing true positives whose windows happen to be narrow. The default `min_window_len >= 16` ensures the gate only activates when there are enough bytes for statistically meaningful class proportions.

**When enabled**: Rules with `char_class` configured, or auto-enabled for entropy-gated rules with `min_bits_per_byte >= 3.0` (defaults: `max_lower_pct: 95`, `min_window_len: 32`).

**Performance**: O(window.len()) with 16-byte SIMD throughput. Runs before the regex to eliminate ~5–15% of windows cheaply.

### 6. Value Suppressor Gate (Post-Match)

```rust
if let Some(vs) = value_suppressors {
    if contains_any_memmem(secret_bytes, vs) {
        return; // suppress this match
    }
}
```

**Purpose**: Discard findings whose extracted secret value contains a known placeholder or example pattern (e.g., `EXAMPLE`, `DUMMY_TOKEN`).

**When evaluated**: After regex matching, secret span extraction, and entropy gating — before local context checks.

**Matching semantics**: Case-sensitive memmem on the extracted secret bytes (not the full window). Uses `PackedPatterns` for the pattern set.

**Performance**: O(secret_len × pattern_count) memmem searches, only on confirmed matches. Does not reduce regex work but eliminates false positives that entropy/regex cannot distinguish.

**Use case**: Suppressing well-known test/example values that structurally resemble real secrets.

### 7. Local Context Gate (Post-Match)

Local context gates run **after** regex matching and secret extraction. They
inspect a bounded lookaround slice (same line) to validate micro-context such as
assignment separators, quoting, or key-name hints. These checks are:

- **Bounded**: O(k) for small lookbehind/lookahead windows
- **Allocation-free**: byte scans only
- **Fail-open**: when line boundaries are not found inside the lookaround range

Local context gates are rule-selective and opt-in via rule config.
They apply uniformly in raw, UTF-16, and stream-decoded validation paths.

### 8. Emit-Time Safelist Suppression

Emit-time safelist/offline filtering operates in three safelist tiers plus offline validation:

**Tier 1 — Context-window safelist** (root findings only): Before recording a
finding, emit paths run a safelist check only when the finding's
`step_id == STEP_ROOT`, using the root-context slice derived from
`root_hint_start..root_hint_end`.

- Step-root findings matching safelist patterns are suppressed immediately.
- Suppressed findings increment `ScanScratch::safelist_suppressed` in instrumentation builds.
- Findings with `step_id != STEP_ROOT` bypass this check.
- Root-semantic UTF-16 findings carry a `Utf16Window` step as their own
  `step_id`, so they bypass safelist but still participate in offline
  validation via their parent step.

**Tier 2 — Secret-bytes safelist** (all findings): After the context-window
check, the extracted secret bytes are matched against a curated 9-pattern
subset of the safelist. This tier runs on **all** findings, including
decoded/transform-derived values, because placeholder values like `"hunter2"`,
`"0123456789"`, or base64 example literals are equally fake regardless of
their encoding layer. Patterns for known placeholder values use `^...$`
anchoring instead of `\b` word boundaries, preventing false suppression of
composite secrets that contain placeholder words as hyphen- or dot-separated
segments (e.g., `key-null-safety-9xK2mB`).

- Suppressed findings increment `ScanScratch::secret_bytes_safelist_suppressed` in instrumentation builds.
- Context-anchored patterns and short substrings (e.g., "mock") that risk
  false suppression of real secrets are excluded from this tier.

**Tier 3 — UUID-format quick-reject** (all findings): After the secret-bytes
check, the extracted value is tested against the canonical UUID shape
(8-4-4-4-12 hyphenated hex, case-insensitive, structural-only — no
version/variant validation per RFC 9562). Hyphenated format only — 32-char
hex without hyphens is deliberately excluded because it collides with
MD5/SHA/AES key representations. Full-value anchoring (`^...$`) prevents the
TruffleHog #1953 false-negative pattern on composite secrets. The check is
gated per-rule by `RuleCompiled::uuid_format_secret()` so that rules whose
capture group is exactly UUID-format (e.g., Heroku, Snyk API keys) bypass
suppression.

- Suppressed findings increment `ScanScratch::uuid_format_suppressed` in instrumentation builds.

### 9. Offline Structural Validation

After safelist suppression, findings for rules with an `offline_validation`
gate are checked by `compute_offline_verdict()`. This runs inline at
emission time, before the finding consumes a `max_findings_per_chunk` slot.

- Only **root-semantic** findings are validated (`parent_step_id == STEP_ROOT`).
  This includes root-level UTF-16 findings whose own `step_id` is a
  `Utf16Window` decode step — the check uses the **parent** step ID.
- Suppression requires both an [`Invalid`](OfflineVerdict::Invalid) verdict
  and the spec's `suppresses_on_invalid` flag.
- `Valid` and `Indeterminate` verdicts always pass through.
- Suppressed findings increment `ScanScratch::offline_suppressed` in instrumentation builds.

---

## has_assignment_value_shape: Assignment Structure Validation

```rust
fn has_assignment_value_shape(window: &[u8]) -> bool
```

A specialized precheck for patterns like `api_key=AKIAIOSFODNN7EXAMPLE` that detects assignment structure without regex overhead.

### Algorithm

1. **Find separator**: Search for `=`, `:`, or `>` (for `=>`)
2. **Skip whitespace/quotes**: After separator, skip spaces, tabs, quotes (`"`, `'`, `` ` ``), and extra separators
3. **Validate token length**: Count consecutive alphanumeric/underscore/hyphen/dot characters; require minimum 10 characters

### Examples

✓ `api_key=AKIAIOSFODNN7EXAMPLE` (22-char token after `=`)

✓ `token: abcdefghij1234567890` (20-char token after `:`)

✓ `key="longtokenvalue"` (14-char token, quotes skipped)

✗ `key=short` (4-char token, < 10 minimum)

✗ `token=` (no token after separator)

✗ `api_key AKIAIOSFODNN7EXAMPLE` (no separator)

### Performance

O(window.len()) byte scan; conservative filter that only produces true rejections (no false negatives).

---

## Regex Execution

Window validation uses Rust `regex::bytes::Regex` with reusable capture locations (not Hyperscan) to avoid per-match allocations:

```rust
let mut locs = scratch.capture_locs[rule_id as usize]
    .take()
    .expect("capture locations missing for rule");

for_each_capture_match(&rule.re, &mut locs, search_window, |locs, start, end| {
    let match_start = search_start + start;
    let match_end = search_start + end;
    let (_secret_start, _secret_end) = extract_secret_span_locs_raw(
        locs,
        rule.secret_group_raw(),
        rule.has_secret_group_override(),
    );
    // Process match...
});

scratch.capture_locs[rule_id as usize] = Some(locs);
```

### Key Points

- **Capture groups**: The regex stores named and positional capture groups
- **Full match**: Callback `start..end` is group 0 (full match)
- **Search window**: For Raw variant, regex starts at `search_start` (anchor hint minus back-scan margin)
- **Multiple matches**: Helper iteration walks non-overlapping matches and handles empty-width progress safely

### Coordinate Adjustment

Regex offsets are relative to `search_window`, so they must be re-based to window coordinates:

```rust
let match_start = search_start + start;
let match_end = search_start + end;
```

Then again adjusted to buffer coordinates for finding recording:

```rust
let match_span_in_buf = (w.start + match_start)..(w.start + match_end);
```

---

## Entropy Checking: entropy_gate_outcome Implementation

Entropy gating filters matches based on two complementary metrics computed from
the extracted secret bytes, eliminating tokens unlikely to be credentials:

1. **Shannon entropy** (always checked): measures average information content.
   Rejects highly repetitive or structured tokens (e.g., all-same-byte, sequential digits).
2. **Min-entropy** (optional, per NIST SP 800-90B): measures worst-case predictability.
   `H_inf = -log2(p_max) = log2(n) - log2(max_bin_count)`. Rejects distributions
   where one byte value dominates even though the overall Shannon entropy looks moderate.

Both metrics are computed in a single fused pass over the 256-bin histogram
(`compute_entropy_metrics`), adding ~1 instruction per bin (cmov for max tracking).

### Invocation

```rust
// Extract secret span first so entropy is evaluated on the
// secret itself, not the full match.
let (secret_start, secret_end) = extract_secret_span_locs_raw(
    locs, secret_group_raw, has_secret_group_override,
);
let secret_bytes = &window[secret_start..secret_end];

let entropy_outcome = post_match_entropy_outcome(
    entropy, secret_bytes, scratch, &self.entropy_log2,
);
if matches!(entropy_outcome, Some(EntropyGateOutcome::Failed)) {
    return;
}
```

### Parameters

- `entropy`: Optional `EntropyCompiled` with Shannon threshold, optional digit-only penalty flag, min-entropy threshold, and length bounds
- `secret_bytes`: The extracted secret bytes to evaluate
- `scratch`: Mutable scan scratch (provides entropy histogram scratch space)
- `entropy_log2`: Pre-computed log2 lookup table for efficiency

### Behavior

- Evaluates entropy on the **extracted secret** bytes, not the full regex match or window
- If `digit_penalty` is enabled and the evaluated entropy slice is all ASCII digits, subtracts `1.2 / log2(len)` from Shannon before threshold comparison
- Shannon entropy is checked first (rejects ~80-90% of non-secrets)
- Min-entropy is checked second when `min_entropy_bits_per_byte` is set
- Matches shorter than configured minimum length return `BypassedShortLen` (pass-through for detection, zero confidence contribution)
- On measured failure (`Failed`), the callback returns early for that match and continues scanning other matches

### Rationale

Entropy gating kept separate from gate checks because:
1. It's only applied to matches, not the whole window
2. Multiple matches per window may pass/fail independently
3. Failure doesn't invalidate other potential matches in the window

---

## Secret Span Extraction

The `extract_secret_span_locs_raw()` helper extracts the sensitive portion of the
match using a priority hierarchy:

### Extraction Priority

1. **Configured secret_group**: If rule specifies `secret_group` and that capture group is non-empty
2. **First non-empty capture group (1..N)**: Group 1 is checked first as a fast path (Gitleaks convention), then groups 2..N are scanned for the first non-empty match
3. **Full match (group 0)**: Fallback when no capture groups are non-empty

### Example

For regex pattern `api_key\s*=\s*([\w-]+)`:

- Full match (group 0): `api_key = AKIAIOSFODNN7EXAMPLE`
- Capture group 1: `AKIAIOSFODNN7EXAMPLE` ← used as secret span

### Recording Invariant

The `root_hint_*` fields use the **full match span** (not secret span), not the window span:

```rust
let root_span_hint = root_hint.clone().unwrap_or(match_span_in_buf);

scratch.push_finding(FindingRec {
    span_start: secret_start,  // Secret portion
    span_end: secret_end,
    root_hint_start: base_offset + root_span_hint.start as u64,  // Full match
    root_hint_end: base_offset + root_span_hint.end as u64,
});
```

**Why?** The `drop_prefix_findings()` deduplication logic (in parent modules) uses `root_hint_end` to determine whether a finding should be kept during chunked scans. Using the full match span handles trailing context correctly (e.g., delimiter `;` extending into new bytes).

---

## Finding Recording

Findings are recorded into the provided `ScanScratch` structure with drop-hint and normalization data to support dedupe and chunk-boundary safety. The engine hot path uses `scratch.push_finding_with_drop_hint(...)`, while the scheduler adapters stage data in `scratch.tmp_findings` plus companion arrays (`tmp_drop_hint_end`, `tmp_norm_hash`) for the caller to commit.

```rust
scratch.push_finding_with_drop_hint(
    FindingRec {
    file_id,
    rule_id,
    span_start: span_in_buf.start as u32,
    span_end: span_in_buf.end as u32,
    root_hint_start: base_offset + root_span_hint.start as u64,
    root_hint_end: base_offset + root_span_hint.end as u64,
    dedupe_with_span,
    step_id,
    confidence_score,
    },
    norm_hash,
    drop_hint_end,
    dedupe_with_span,
);
```

### FindingRec Fields

| Field | Type | Meaning |
|-------|------|---------|
| `file_id` | `FileId` | File identifier for finding source |
| `rule_id` | `u32` | Rule that matched |
| `span_start` | `u32` | Secret span start in decoded-stream or buffer |
| `span_end` | `u32` | Secret span end (exclusive) |
| `root_hint_start` | `u64` | Full match start (file offset for deduplication) |
| `root_hint_end` | `u64` | Full match end (file offset for deduplication) |
| `step_id` | `StepId` | Decode chain reference (enables span mapping) |
| `dedupe_with_span` | `bool` | Whether `span_start`/`span_end` participate in dedupe |
| `confidence_score` | `i8` | Additive 0–10 score computed from per-finding evidence (measured entropy pass, local keyword hit, assignment-shape signal, offline-valid signal) |

Keyword evidence is evaluated on a clamped local slice around the full regex
match: `match_start.saturating_sub(32) .. min(match_end + 32, hay.len())`.

### Capacity Management

This module records findings directly into scratch. `max_findings_per_chunk` is
enforced at insert time, and overflow increments drop counters.

### Coordinate Spaces

**Raw variant**: Spans are in raw buffer byte offsets

**UTF-16 variants**:
- `span_start`/`span_end`: Decoded UTF-8 byte space
- `root_hint_*`: Full match span mapped back into raw UTF-16 byte offsets, then (when present) through `root_span_map_ctx` for transform-derived buffers
- `step_id`: Points to `DecodeStep::Utf16Window` that stores endianness and parent span for later mapping

---

## UTF-16 Handling

The module supports UTF-16LE and UTF-16BE variants through a unified code path that scans both byte parities when anchors can land on either boundary.

### Decode Budget Enforcement

```rust
let remaining = self.tuning.max_total_decode_output_bytes
    .saturating_sub(scratch.total_decode_output_bytes);
if remaining == 0 {
    return;
}

let max_out = self.tuning.max_utf16_decoded_bytes_per_window
    .min(remaining);
```

Two budget limits:
1. Per-window maximum
2. Total accumulated decoding output limit (across all windows in scan)

### Decoding Process

```rust
let decoded = match variant {
    Variant::Utf16Le => decode_utf16le_to_buf(raw_win, max_out, &mut scratch.utf16_buf),
    Variant::Utf16Be => decode_utf16be_to_buf(raw_win, max_out, &mut scratch.utf16_buf),
    _ => unreachable!(),
};
```

Decoding:
- Outputs to reusable scratch buffer (`scratch.utf16_buf`) to avoid allocation
- Returns on decode-cap overflow (`Utf16DecodeError::OutputTooLarge`)
- Invalid UTF-16 sequences are replaced with U+FFFD during decoding
- Returns if output is empty (no valid data decoded)

### Gate Ordering for UTF-16

Gates are applied in a specific order to minimize decode work:

```
[1] Check decode budget remaining
    ↓
[2] Run confirm_all gate on raw UTF-16 bytes (before decode)
    ↓
[3] Run keywords gate on raw UTF-16 bytes (before decode)
    ↓
[4] Decode UTF-16 → UTF-8
    ↓
[5] Check must_contain gate on decoded UTF-8
    ↓
[6] Apply assignment-shape check on decoded UTF-8
    ↓
[7] Apply char-class gate on decoded UTF-8 (when configured)
    ↓
[8] Run regex on decoded UTF-8
    ↓
[9] Post-match: secret extraction → entropy → value suppressors → local context
    ↓
[10] Emit-time policy: root safelist → secret-bytes safelist → UUID reject → offline validation
    ↓
[11] Compute confidence score and apply `min_confidence` threshold
```

This ordering ensures:
- Cheap gates run before expensive decoding
- Keyword/confirm gates reject windows before wasting decode budget
- must_contain gate runs on decoded UTF-8 (must check decoded content)
- Value suppressors run on extracted secret bytes in decoded space (never raw UTF-16)

---

## Alternative Entry Points

Two additional functions support the decode-then-validate pattern used by other engine components:

### run_rule_on_raw_window_into

```rust
pub(super) fn run_rule_on_raw_window_into(
    &self,
    rule_id: u32,
    rule: &RuleCompiled,
    window: &[u8],
    window_start: u64,
    ...
    found_any: &mut bool,
)
```

For externally-managed windows (already extracted from buffer). Used when:
- Window buffer is managed by caller
- Caller tracks window starting offset
- Caller needs to know if any match passed gates and cleared emit-time policy plus confidence threshold

Uses output parameter (`found_any`) and stages accepted findings in
`scratch.tmp_findings` with aligned sidecars (`tmp_drop_hint_end`, `tmp_norm_hash`).

### run_rule_on_utf16_window_into

```rust
pub(super) fn run_rule_on_utf16_window_into(
    &self,
    rule_id: u32,
    rule: &RuleCompiled,
    variant: Variant,
    raw_win: &[u8],
    window_start: u64,
    ...
    found_any: &mut bool,
)
```

Similar to above but for UTF-16 windows. Handles decoding and validation within caller's window management context.
The function uses `anchor_hint` parity to scan the hinted alignment first, then
the opposite alignment.

---

## Testing

The module includes comprehensive tests for `has_assignment_value_shape`:

- ✓ Basic assignment with `=`, `:`, `=>`
- ✓ Quoted tokens: `"..."`, `'...'`, `` `...` ``
- ✓ Special chars in tokens: `_`, `-`, `.`
- ✓ Boundary conditions: exactly 10 chars passes, 9 chars fails
- ✓ Negative cases: no separator, short tokens, empty values

Located in `crates/scanner-engine/src/engine/window_validate_tests.rs` (included via `#[path]` attribute).

---

## Design Rationale

### Back-Scan Margin (64 bytes)

Accounts for patterns with backward context or mid-match anchors. 64 bytes balances correctness against overhead for most secret patterns.

### Gate Ordering

Gates progress from cheapest (memmem) to most expensive (regex), with slight
variant-specific ordering:
1. Raw: must_contain -> confirm_all -> keywords -> assignment-shape -> char_class
2. UTF-16: confirm_all -> keywords -> decode -> must_contain -> assignment-shape -> char_class
3. Regex: O(n x complexity)
4. Post-match: secret extraction -> entropy -> value suppressors -> local context
5. Emit-time: safelists/offline validation -> evidence-based confidence score -> min_confidence threshold

Early failures save expensive regex execution. Post-match gates run only on
confirmed regex matches, so their cost scales with finding count, not window count.
Root safelist suppression and offline structural validation both run inline at
finding emission time, before the finding occupies a cap slot or triggers
dedup computation.

### Entropy on Extracted Secret

Applied to the extracted secret span, not the full match, because:
- The full match includes non-secret context (key names, assignment operators, quotes) that dilutes the entropy signal
- Evaluating on the full match causes false negatives (high-entropy secrets rejected due to low-entropy surrounding context) and false accepts (low-entropy secrets passed due to high-entropy context)
- Secret group extraction runs before entropy so the gate evaluates only the credential bytes

### UTF-16 Budget Enforcement

Two limits prevent DoS via massive UTF-16 expansion:
- Per-window prevents single huge window from consuming all budget
- Total accumulated prevents many small windows from accumulating

### Scratch-Based Recording

Findings are written to scratch buffers (not directly to materialized results) because:
- Keeps dedupe/drop-hint bookkeeping localized and allocation-free
- Enables downstream processing (materialization, transforms, reporting)
- Preserves consistent sidecar alignment for `norm_hash` and `drop_hint_end`

---

## Invariants and Guarantees

1. Window ranges must be valid for the provided buffer
2. For Raw variant, match spans are in raw byte space
3. For UTF-16 variants, match spans are in decoded UTF-8 byte space
4. root_hint (when present) is in the same coordinate space as base_offset
5. anchor_hint is in window/buffer coordinates (Raw back-scan and UTF-16 parity selection)
6. All early returns occur before findings are recorded
7. Findings are appended or replaced in-place for dedupe preference (never removed or reordered during function execution)
8. Entropy gates continue to next match (not early return)
9. Root safelist suppression, secret-bytes safelist suppression, UUID-format quick-reject, offline structural validation, confidence threshold checks, and cap checks are applied before finding insertion
