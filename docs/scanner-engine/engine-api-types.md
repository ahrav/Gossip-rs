# Engine API Types

Public data types for configuring the scanner engine and reporting results.

## Source of Truth

| File | Purpose |
|------|---------|
| [crates/scanner-engine/src/api.rs](../../crates/scanner-engine/src/api.rs) | All public API types (1,830 lines) |
| [crates/scanner-engine/src/lib.rs](../../crates/scanner-engine/src/lib.rs) | Re-exports for the `scanner-engine` crate |

## Overview

`api.rs` defines the shared configuration and result structs used by the engine
and its callers. Types are intentionally **behavior-free** — the engine performs
validation and enforcement when it is built (`Engine::new`). Hot-path types are
`Copy` where possible and offsets are stored as `u32` to keep scans
allocation-free.

Key design invariants:

- `FileId` and `StepId` are opaque indices valid only for the table/arena that
  created them.
- `DecodeSteps` is bounded by `MAX_DECODE_STEPS` (root step + transform depth).
- `RuleSpec`, `TransformConfig`, and `Tuning` are validated at engine build
  time; invalid combinations panic during construction.
- Hot-path offsets are `u32`; callers must chunk inputs so any single buffer
  fits in `u32::MAX` bytes.

## Type Categories

| Category | Types | Purpose |
|----------|-------|---------|
| [Identifiers](#identifiers) | `FileId`, `StepId` | Opaque arena/table indices |
| [Rule configuration](#rule-configuration) | `RuleSpec`, `AnchorPolicy`, `ValidatorKind`, `TailCharset`, `DelimAfter` | Define detection rules and fast-path validators |
| [Rule gates](#rule-gates) | `EntropySpec`, `CharClassSpec`, `LocalContextSpec`, `TwoPhaseSpec`, `OfflineValidationSpec`, `OfflineVerdict` | Pre/post-match filters that reduce false positives |
| [Transform types](#transform-types) | `TransformConfig`, `TransformId`, `TransformMode`, `Gate` | Control recursive decode passes (URL, Base64) |
| [Scan output](#scan-output) | `FindingRec`, `Finding`, `DecodeStep`, `DecodeSteps`, `Utf16Endianness` | Hot-path finding records and materialized results |
| [Tuning](#tuning) | `Tuning` | Engine-wide performance and DoS-protection knobs |
| [Confidence scoring](#confidence-scoring) | `confidence::*` constants | Additive per-finding evidence weights |
| [Constants](#constants) | `MAX_DECODE_STEPS`, `STEP_ROOT`, `LOCAL_CONTEXT_MAX_LOOKAROUND` | Global limits and sentinels |
| [Feature-gated](#feature-gated-types) | `Base64DecodeStats` | Instrumentation counters (`b64-stats` feature) |

## Identifiers

### `FileId` (line 50)

```rust
pub struct FileId(pub u32);
```

Opaque file identifier indexing into a `FileTable`. Not a filesystem path —
callers must look up metadata in the owning `FileTable`. Derives `Clone`,
`Copy`, `Debug`, `PartialEq`, `Eq`, `Hash`.

**Construction:** Via `FileTable::push` or direct `FileId(n)` when the caller
can guarantee the index is valid.

**Invariant:** Only valid for the `FileTable` that produced it.

### `StepId` (line 61)

```rust
pub struct StepId(pub(crate) u32);
```

Compact index into the decode-step arena. Steps are chained from root to
derived buffers so findings can be reconstructed without cloning on the hot
path. The inner `u32` is `pub(crate)` — external consumers cannot construct
arbitrary values outside of test harnesses.

**Invariants:**
- Only valid while the originating decode-step arena is alive and not reset.
- `STEP_ROOT` (`StepId(u32::MAX)`) is the sentinel for an empty provenance
  chain.
- `Default::default()` returns `STEP_ROOT`.

**Test/harness access:** `StepId::from_raw(u32)` is available under
`#[cfg(any(test, feature = "sim-harness", feature = "test-support"))]`.

## Rule Configuration

### `RuleSpec` (line 687)

The central rule definition struct. Each `RuleSpec` configures one detection
rule: anchor patterns, regex, validation gates, and metadata.

| Field | Type | Description |
|-------|------|-------------|
| `name` | `&'static str` | Rule name for reporting. Must be non-empty. |
| `anchors` | `&'static [&'static [u8]]` | ASCII-ish anchor patterns. UTF-16LE/BE variants are derived automatically. |
| `radius` | `usize` | Bytes around an anchor hit to include in the validation window. |
| `validator` | `ValidatorKind` | Optional fast-path validator; bypasses window/regex when authoritative. Default: `None`. |
| `two_phase` | `Option<TwoPhaseSpec>` | Optional two-phase confirm + expand. |
| `must_contain` | `Option<&'static [u8]>` | Cheap byte-substring pre-check before regex. Must be non-empty when set. |
| `keywords_any` | `Option<&'static [&'static [u8]]>` | Keyword gate (any-of) checked in the validation window. Compiled into raw + UTF-16LE/BE variants like anchors. |
| `value_suppressors_any` | `Option<&'static [&'static [u8]]>` | Post-match filter: suppress findings whose extracted secret contains any of these byte literals. Case-sensitive. |
| `entropy` | `Option<EntropySpec>` | Post-regex entropy gate on extracted secret bytes. |
| `char_class` | `Option<CharClassSpec>` | Pre-regex character-class distribution gate. Auto-enabled when `entropy.min_bits_per_byte >= 3.0`. |
| `local_context` | `Option<LocalContextSpec>` | Post-extraction local context gate (assignment shape, quoting, key names). |
| `offline_validation` | `Option<OfflineValidationSpec>` | Post-extraction structural validation (CRC, checksums). |
| `uuid_format_secret` | `bool` | When `true`, bypasses UUID-format quick-reject in the safelist. Default: `false`. |
| `secret_group` | `Option<u16>` | Capture group index for secret extraction. `None` = first non-empty group in 1..N, falling back to full match. |
| `min_confidence` | `Option<i8>` | Per-rule confidence threshold (0..=10). `None` = auto-derived from compiled gates. |
| `re` | `Regex` | Bytes regex (no UTF-8 assumptions). |

**Validation (`assert_valid`, line 838):** Panics on:
- Empty `name`.
- Invalid `validator`, `two_phase`, `entropy`, `char_class`, `local_context`,
  or `offline_validation` sub-specs.
- Empty `must_contain`, `keywords_any`, or `value_suppressors_any`.
- `secret_group` referencing a non-existent regex capture group.
- `min_confidence` outside `0..=10`.

### `AnchorPolicy` (line 1462)

```rust
pub enum AnchorPolicy {
    PreferDerived,
    ManualOnly,
    DerivedOnly,
}
```

Controls how anchors are selected at engine compilation:

| Variant | Behavior |
|---------|----------|
| `PreferDerived` | Derive anchors from regex AST via `regex2anchor`, fall back to manual `RuleSpec::anchors` if derivation fails. **Default.** |
| `ManualOnly` | Use only manual anchors; skip derivation. |
| `DerivedOnly` | Use only derived anchors; ignore manual anchors entirely. |

### `ValidatorKind` (line 479)

Fast-path validator that can confirm token-like rules at anchor hits, bypassing
window accumulation and regex evaluation.

| Variant | Fields | Description |
|---------|--------|-------------|
| `PrefixFixed` | `tail_len: u16`, `tail: TailCharset`, `require_word_boundary_before: bool`, `delim_after: DelimAfter` | Prefix + fixed-length tail + optional boundary checks. |
| `PrefixBounded` | `min_tail: u16`, `max_tail: u16`, `tail: TailCharset`, `require_word_boundary_before: bool`, `delim_after: DelimAfter` | Prefix + bounded-length tail (greedy, with backtracking for delimiter). Invariant: `min_tail <= max_tail`. |
| `AwsAccessKey` | — | Special-case validator for AWS access key IDs. |
| `None` | — | No fast validator; always use regex/window path. Built-in rules currently use this. |

**Precondition:** Only use fast validators when anchors are match-start aligned
in raw bytes.

### `TailCharset` (line 558)

Character classes for fast-path validator tail bytes. All are strict ASCII;
non-ASCII bytes terminate the tail.

| Variant | Character set |
|---------|---------------|
| `UpperAlnum` | `[A-Z0-9]` |
| `Alnum` | `[A-Za-z0-9]` |
| `LowerAlnum` | `[a-z0-9]` |
| `AlnumDashUnderscore` | `[A-Za-z0-9_-]` |
| `Sendgrid66Set` | `[A-Za-z0-9=_\-.]` |
| `DatabricksSet` | `[a-hA-H0-9]` |
| `Base64Std` | `[A-Za-z0-9+/]` |

### `DelimAfter` (line 541)

Post-match delimiter requirement for fast-path validators.

| Variant | Behavior |
|---------|----------|
| `None` | No delimiter requirement. |
| `GitleaksTokenTerminator` | Requires `['"\|\s\|;\|\x60]`, escaped newlines (`\\[nr]`), or end-of-input after the tail. |

## Rule Gates

Gates are pre- or post-match filters evaluated in the detection pipeline.
They reduce false positives at varying cost.

### `EntropySpec` (line 912)

Shannon entropy + optional min-entropy gate evaluated on extracted secret bytes
(not the full match window).

| Field | Type | Description |
|-------|------|-------------|
| `min_bits_per_byte` | `f32` | Shannon entropy floor in bits/byte. Range: `[0.0, 8.0]`. |
| `min_len` | `usize` | Matches shorter than this pass without entropy checks. Must be `>= 1`. |
| `max_len` | `usize` | First N bytes used for entropy calculation. Must be `>= min_len`. |
| `min_entropy_bits_per_byte` | `Option<f32>` | Min-entropy floor (NIST SP 800-90B `H_inf = -log2(p_max)`). `None` = disabled. Range: `[0.0, 8.0]`. |
| `digit_penalty` | `bool` | When `true` and the (possibly capped) entropy slice is all ASCII digits, subtract `DIGIT_ONLY_PENALTY_NUMERATOR / log2(len)` from Shannon. Skipped for `len == 1`. |

**Algorithm:**
1. Matches shorter than `min_len` pass unconditionally.
2. Matches longer than `max_len` are capped (first `max_len` bytes).
3. If `digit_penalty` is enabled and the slice is all digits, adjust Shannon.
4. Check Shannon entropy against `min_bits_per_byte`.
5. If `min_entropy_bits_per_byte` is set, check min-entropy second.

### `CharClassSpec` (line 987)

Pre-regex character-class distribution gate. Rejects windows dominated by
lowercase ASCII (i.e., English prose) via SIMD classification.

| Field | Type | Description |
|-------|------|-------------|
| `max_lower_pct` | `u8` | Maximum percentage of lowercase ASCII bytes allowed. Range: `0–100`. |
| `min_window_len` | `u16` | Minimum window length for the gate to apply. Must be `>= 16`. Shorter windows pass unconditionally. |

**Auto-enabling:** When `None` in YAML and `entropy.min_bits_per_byte >= 3.0`,
the YAML parser auto-enables with `max_lower_pct: 95`, `min_window_len: 32`.

### `LocalContextSpec` (line 613)

Post-extraction local context gate. Examines bytes surrounding a confirmed
regex match to check whether it looks like a real secret in use.

| Field | Type | Description |
|-------|------|-------------|
| `lookbehind` | `usize` | Max bytes before the secret span. Capped at `LOCAL_CONTEXT_MAX_LOOKAROUND` (1024). |
| `lookahead` | `usize` | Max bytes after the secret span. Capped at `LOCAL_CONTEXT_MAX_LOOKAROUND` (1024). |
| `require_same_line_assignment` | `bool` | Require `=`, `:`, or `=>` on the same line before the secret. |
| `require_quoted` | `bool` | Require matching quotes (`"`, `'`, or `` ` ``) around the secret. |
| `key_names_any` | `Option<&'static [&'static [u8]]>` | Key name literals (any-of) that must appear on the same line before the secret. Must be non-empty when `Some`. |

**Evaluation order:**
1. **Quoting** — fail-open if secret span is outside the window.
2. **Line bounds** — computed from lookbehind/lookahead. If no newlines found, remaining line-based checks are skipped (fail-open).
3. **Assignment separator** — line slice before secret must contain `=`, `:`, or `=>`.
4. **Key names** — at least one literal must appear before the secret on the same line.

Checks 3 and 4 are independent; both must pass if both are enabled.
All checks are bounded by `LOCAL_CONTEXT_MAX_LOOKAROUND` and allocation-free
(`memchr` / `memmem` on small byte windows).

### `TwoPhaseSpec` (line 437)

Two-phase rule: confirm in a smaller seed window, then expand to full radius.

| Field | Type | Description |
|-------|------|-------------|
| `seed_radius` | `usize` | Radius for the seed window. Must be `<= full_radius`. |
| `full_radius` | `usize` | Radius for the expanded window after confirmation. |
| `confirm_any` | `&'static [&'static [u8]]` | Patterns that must appear in the seed window. Must be non-empty. |

**Algorithm:**
1. Check `confirm_any` inside the seed window (`seed_radius`).
2. If any confirm hit, expand to `full_radius` and run regex validation.

### `OfflineValidationSpec` (line 1026)

Post-extraction structural validation applied before emitting a finding.
No network access required.

| Variant | Fields | Description |
|---------|--------|-------------|
| `Crc32Base62` | `prefix_skip: u8`, `payload_len: u8`, `checksum_len: u8` | CRC-32 encoded as base-62 appended to the token. `payload_len > 0`, `checksum_len` in `1..=6`. |
| `GithubFinegrainedPat` | — | GitHub fine-grained PAT checksum. |
| `GrafanaServiceAccount` | — | Grafana service-account token checksum. |
| `AwsAccessKey` | — | AWS access key ID check-digit validation. |
| `SentryOrgToken` | — | Sentry org-auth-token base64 + JSON payload prefix check. |
| `PyPiToken` | — | PyPI upload token macaroon V2 binary header check (base64url). |
| `SlackToken` | — | Slack API token prefix-dispatch with per-format segment validation. |

All variants suppress findings on `Invalid` verdict
(`suppresses_on_invalid()` returns `true` for all).

### `OfflineVerdict` (line 1104)

Result of an offline structural validation check.

| Variant | Confidence contribution | Finding emitted? |
|---------|------------------------|------------------|
| `Valid` | `confidence::OFFLINE_VALID` (+5) | Yes |
| `Invalid` | 0 | Suppressed (when spec opts in) |
| `Indeterminate` | 0 | Yes (check could not apply) |

## Transform Types

### `TransformId` (line 104)

Identifies a supported transform for derived-buffer scanning.

| Variant | Description | CLI name |
|---------|-------------|----------|
| `UrlPercent` | URL percent decoding (optionally `+` as space). | `url` |
| `Base64` | Base64 decoding (optional whitespace allowances). | `base64` |

**Associated items:**
- `TransformId::ALL: &[TransformId]` — all variants in definition order (line 1684).
- `TransformId::cli_name(self) -> &'static str` — canonical CLI name for `--transforms` (line 1692).

### `TransformMode` (line 116)

Controls when a transform is applied during scanning.

| Variant | Behavior |
|---------|----------|
| `Disabled` | Never apply. |
| `Always` | Always apply, subject to span and budget caps. |
| `IfNoFindingsInThisBuffer` | Skip if the current buffer already produced findings. Explicit correctness trade-off: can miss findings in nested encodings. Each buffer tracks its own "has findings" flag independently. |

### `Gate` (line 143)

Gate policy for expensive transform decoding. Runs after decode but before
the decoded buffer is enqueued for recursive scanning.

| Variant | Behavior |
|---------|----------|
| `None` | No gate; decode all candidate spans (subject to caps). |
| `AnchorsInDecoded` | Stream-decode and proceed only if decoded bytes contain any anchor variant (raw + UTF-16LE/BE). Sound only when anchors are required; false negatives possible with optional anchors. |

### `TransformConfig` (line 170)

Configuration for a single transform stage. Lengths are in bytes of encoded
input unless otherwise noted.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `TransformId` | Transform kind. |
| `mode` | `TransformMode` | When this transform is applied. |
| `gate` | `Gate` | Gate policy for decoded output. |
| `min_len` | `usize` | Minimum encoded length for span detection. |
| `max_spans_per_buffer` | `usize` | Cap on candidate spans per buffer. Must be `> 0` when enabled. |
| `max_encoded_len` | `usize` | Maximum encoded length for a span. Must be `>= min_len`. |
| `max_decoded_bytes` | `usize` | Max decoded bytes per span. Must be `> 0` when enabled. |
| `plus_to_space` | `bool` | Treat `+` as space. Only used for `UrlPercent`. |
| `base64_allow_space_ws` | `bool` | Allow space as whitespace during Base64 span detection. Only used for `Base64`. |

**Invariants (enforced by `assert_valid`, line 206):**
- `max_encoded_len >= min_len`.
- When `mode != Disabled`: `max_spans_per_buffer > 0` and `max_decoded_bytes > 0`.

## Scan Output

### `FindingRec` (line 375)

Compact finding record stored during scanning. Fixed-width and `Copy` for
ring-buffer-friendly hot-path accumulation. Materialized into `Finding` later.

| Field | Type | Description |
|-------|------|-------------|
| `file_id` | `FileId` | Source file id. |
| `rule_id` | `u32` | Engine-local rule index. |
| `span_start` | `u32` | Span start in current buffer (byte index). |
| `span_end` | `u32` | Span end in current buffer (byte index). |
| `root_hint_start` | `u64` | Best-effort root span hint start (absolute file byte offset). |
| `root_hint_end` | `u64` | Best-effort root span hint end (absolute file byte offset). |
| `dedupe_with_span` | `bool` | Whether `span_start`/`span_end` participate in dedup. `false` for transform-derived findings with precise root mapping. |
| `step_id` | `StepId` | Decode-step chain id. `STEP_ROOT` for root-buffer findings. |
| `confidence_score` | `i8` | Additive confidence from evidence signals (0–10). Does not participate in dedup. |

**Confidence score composition:**

| Signal | Weight | Condition |
|--------|--------|-----------|
| Entropy passed | +1 | Measured on extracted secret bytes |
| Local keyword hit | +2 | Keyword found near match span |
| Assignment shape | +2 | `key = value` pattern detected |
| Offline validation valid | +5 | CRC/charset check passed |

Findings below the rule's `min_confidence` threshold are suppressed before
output.

### `Finding` (line 338)

Materialized, user-facing finding with full provenance.

| Field | Type | Description |
|-------|------|-------------|
| `rule` | `&'static str` | Rule name. |
| `span` | `Range<usize>` | Span in the final representation (after applying `decode_steps`). |
| `root_span_hint` | `Range<usize>` | Best-effort hint into the root buffer. For file-backed scans, absolute byte offset within the file. |
| `decode_steps` | `DecodeSteps` | Inline fixed-capacity chain from root to the representation where `span` applies. |

### `DecodeStep` (line 305)

A single step in the provenance chain.

| Variant | Fields | Description |
|---------|--------|-------------|
| `Transform` | `transform_idx: usize`, `parent_span: Range<usize>` | Deterministic via `transform_idx` (index into `Engine::transforms`). `parent_span` is a byte range in the parent. |
| `Utf16Window` | `endianness: Utf16Endianness`, `parent_span: Range<usize>` | Local UTF-16 decode step. Consumer replays by decoding `parent_span` as UTF-16. |

### `DecodeSteps` (line 327)

```rust
pub type DecodeSteps = FixedVec<DecodeStep, MAX_DECODE_STEPS>;
```

Fixed-capacity decode-step chain stored inline in `Finding`. Bounded by
`MAX_DECODE_STEPS` (8). Steps are ordered root to leaf.

### `Utf16Endianness` (line 287)

```rust
pub enum Utf16Endianness {
    Le,
    Be,
}
```

Tags which endianness produced a UTF-16 anchor hit so downstream decode steps
can replay the conversion. The engine derives UTF-16LE and UTF-16BE variants
of every ASCII anchor and scans for both when NUL bytes are present.

## Tuning

### `Tuning` struct (line 1366)

Engine-wide performance and DoS-protection knobs. Every cap bounds worst-case
CPU or memory cost. When exceeded, work is **dropped** (not queued) — the
engine favors bounded latency over completeness.

| Field | Type | Description |
|-------|------|-------------|
| `merge_gap` | `usize` | Max gap (bytes) between adjacent anchor-hit windows to merge. Typical: 64–256. |
| `max_windows_per_rule_variant` | `usize` | Window count limit per (rule, anchor-variant) pair before pressure-coalesce. |
| `pressure_gap_start` | `usize` | Starting gap for pressure-coalesce pass. Must be `> 0`. Doubles each retry. |
| `max_anchor_hits_per_rule_variant` | `usize` | Safety valve: above this, all hits collapse into one range. Prevents O(n²) merge. Must be `> 0`. |
| `max_utf16_decoded_bytes_per_window` | `usize` | Max decoded UTF-8 bytes from UTF-16 window conversion. |
| `max_transform_depth` | `usize` | Max recursive transform depth per work-item chain. Must be `<= MAX_DECODE_STEPS - 1`. |
| `max_total_decode_output_bytes` | `usize` | Global byte budget for all decoded output in a single scan call. |
| `max_work_items` | `usize` | Hard cap on enqueued child buffers (decoded work items) per scan. |
| `max_findings_per_chunk` | `usize` | Hard cap on findings per chunk. Excess silently dropped. |
| `scan_utf16_variants` | `bool` | Whether to scan UTF-16 anchor variants at runtime. `false` skips even if compiled. |

**Trade-offs:**
- **Window coalescing** limits regex work at the cost of wider windows (more
  false positives).
- **Decode budgets** cap recursive transform work; exceeding them silently
  discards derived buffers (missed nested findings).
- **Finding cap** enforced at insertion time; later findings in the same
  chunk are dropped.

**Validation (`assert_valid`, line 1425):**
- `max_anchor_hits_per_rule_variant > 0`.
- `pressure_gap_start > 0` (avoids infinite coalesce loops).
- Additional cross-field checks performed by `Engine::new`.

## Confidence Scoring

### `confidence` module (line 1134)

Score constants for the additive per-finding confidence model. Evidence is
collected per finding at each emission site in `window_validate.rs`.

| Constant | Value | Description |
|----------|-------|-------------|
| `ENTROPY_PASS` | `1` | Entropy gate passed (weak baseline). |
| `KEYWORD_PRESENT` | `2` | Local keyword found within 32 bytes of match span (moderate). |
| `ASSIGNMENT_SHAPE` | `2` | Secret follows `key = value` pattern (moderate). |
| `OFFLINE_VALID` | `5` | Offline structural validation passed — near-cryptographic proof (strong). |

Phase 1 range: 0–10, well within `i8`. Suppress-only gates (must-contain,
value suppressors, safelists) contribute 0.

**Auto-derived `min_confidence` defaults (when `RuleSpec::min_confidence` is `None`):**
- Keyword + entropy gates present → `KEYWORD_PRESENT + ENTROPY_PASS` = 3
- Assignment-shape check enabled → `ASSIGNMENT_SHAPE` = 2
- Otherwise → 0

Offline validation is excluded from auto-derivation (signal only fires on
root-semantic findings).

## Constants

| Constant | Type | Value | Line | Description |
|----------|------|-------|------|-------------|
| `MAX_DECODE_STEPS` | `usize` | `8` | 67 | Hard cap on decode-step chains. Must be `>= Tuning::max_transform_depth + 1`. |
| `STEP_ROOT` | `StepId` | `StepId(u32::MAX)` | 70 | Sentinel for root of a provenance chain. |
| `LOCAL_CONTEXT_MAX_LOOKAROUND` | `usize` | `1024` | 578 | Max lookaround per side for local context gates. |

## Compile-Time Size Assertions

The following compile-time assertions enforce layout invariants:

| Assertion | Line | Purpose |
|-----------|------|---------|
| `size_of::<FindingRec>() <= 48` | 422 | `FindingRec` must fit in 48 bytes (3 cache-line halves on x86-64). Keeps per-finding arena slots cache-friendly. |
| `confidence::OFFLINE_VALID <= 10` | 1146 | Offline-valid score fits Phase 1 ceiling. |
| `(KEYWORD_PRESENT + ENTROPY_PASS) <= 10` | 1147 | Combined keyword+entropy score fits Phase 1 ceiling. |
| `ASSIGNMENT_SHAPE <= 10` | 1148 | Assignment-shape score fits Phase 1 ceiling. |

## Feature-Gated Types

### `Base64DecodeStats` (line 236, `b64-stats` feature)

Instrumentation counters for base64 decode/gate operations. Counters saturate
on overflow. Only available when the `b64-stats` feature is enabled.

| Field | Type | Description |
|-------|------|-------------|
| `spans` | `u64` | Base64 spans considered (after span caps). |
| `span_bytes` | `u64` | Total encoded bytes across considered spans. |
| `pre_gate_checks` | `u64` | Spans checked by the pre-decode gate. |
| `pre_gate_pass` | `u64` | Spans that passed the pre-decode gate. |
| `pre_gate_skip` | `u64` | Spans skipped by the pre-decode gate. |
| `pre_gate_skip_bytes` | `u64` | Encoded bytes skipped by the pre-decode gate. |
| `decode_attempts` | `u64` | Spans sent to the base64 decoder. |
| `decode_attempt_bytes` | `u64` | Encoded bytes sent to the decoder. |
| `decode_errors` | `u64` | Failed/truncated/empty decode attempts. |
| `decoded_bytes_total` | `u64` | Total decoded bytes produced. |
| `decoded_bytes_kept` | `u64` | Decoded bytes kept (anchor hit). |
| `decoded_bytes_wasted_no_anchor` | `u64` | Discarded: no anchor in decoded output. |
| `decoded_bytes_wasted_error` | `u64` | Discarded: decode error/truncation. |

## Policy-Hash Encoding

Every configuration type implements `encode_policy(&self, out: &mut Vec<u8>)`,
producing a deterministic, order-invariant byte string. This is hashed to form
the *policy hash* — a fingerprint of the full scan configuration used by
`src/git_scan/policy_hash.rs` to detect configuration changes between runs.

**Stability contract:** any semantic change to encodings (field additions,
reorderings, tag value changes) requires a version bump in the policy-hash
module. Failing to do so causes false cache hits.

Types with `encode_policy`:
`RuleSpec`, `TwoPhaseSpec`, `EntropySpec`, `CharClassSpec`,
`OfflineValidationSpec`, `ValidatorKind`, `TailCharset`, `DelimAfter`,
`TransformConfig`, `TransformId`, `TransformMode`, `Gate`, `Tuning`.

## Re-exports

`lib.rs` (line 56–62) re-exports the following from `api.rs` as public API:

```
AnchorPolicy, CharClassSpec, DecodeStep, DecodeSteps, DelimAfter,
EntropySpec, FileId, Finding, FindingRec, Gate,
LOCAL_CONTEXT_MAX_LOOKAROUND, LocalContextSpec, MAX_DECODE_STEPS,
OfflineValidationSpec, OfflineVerdict, RuleSpec, STEP_ROOT, StepId,
TailCharset, TransformConfig, TransformId, TransformMode, Tuning,
TwoPhaseSpec, Utf16Endianness, ValidatorKind
```

`Base64DecodeStats` is re-exported conditionally under the `b64-stats` feature
(line 55).

## Gate Evaluation Pipeline

For reference, the order in which rule gates evaluate during the scan pipeline:

```
Anchor hit
  │
  ├─ ValidatorKind fast path (if non-None) ──→ emit or fall through
  │
  ├─ must_contain (byte substring pre-check)
  ├─ confirm_all (multi-literal AND gate from regex literal islands)
  ├─ keywords_any (window keyword gate)
  ├─ assignment_shape (pre-regex structural check)
  ├─ char_class (pre-regex lowercase-dominated rejection)
  │
  ├─ Regex evaluation
  │
  ├─ entropy (post-regex, on extracted secret bytes)
  ├─ value_suppressors_any (post-extraction suppression)
  ├─ local_context (post-extraction context checks)
  ├─ offline_validation (post-extraction structural check)
  ├─ min_confidence threshold (suppress if score too low)
  │
  └─ FindingRec emitted
```
