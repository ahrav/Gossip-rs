# Engine Offline Validation Module

**File**: `crates/scanner-engine/src/engine/offline_validate.rs`

## Module Purpose

The offline validation module performs deterministic, network-free structural
checks on extracted secret bytes to reject false positives before findings reach
the output sink. Each validator exploits token-specific invariants — CRC
checksums, base-32 check digits, binary header signatures, segment counts — to
confirm or reject a candidate without any I/O.

Offline validation runs **inline at emission time** in `window_validate.rs`
(`apply_emit_time_policy`, Gate 14 in the window validation pipeline). It
operates only on root-semantic findings (`parent_step_id == STEP_ROOT`) and
occurs *after* safelist suppression but *before* confidence scoring and the
`max_findings_per_chunk` cap.

### Design Philosophy

- **Deterministic**: Every validator is a pure function of the secret bytes and
  the spec parameters. No randomness, no ambient state.
- **No network**: Validators never open sockets, query APIs, or check
  revocation lists. They verify structural invariants that a legitimate token
  must satisfy.
- **Conservative verdicts**: The three-verdict hierarchy (`Valid`, `Invalid`,
  `Indeterminate`) is asymmetric by design. `Invalid` requires *positive proof*
  of structural failure; anything uncertain stays `Indeterminate` and the
  finding passes through.
- **No heap allocation**: All decode buffers are stack-local (`[u8; N]`) to keep
  the hot path allocation-free.
- **No regex or I/O**: Validators work on the already-extracted `&[u8]` slice;
  they must not compile regexes, open files, or make network calls.

---

## Verdict Hierarchy

Every validator returns one of three outcomes defined in `api.rs`:

| Verdict         | Meaning                                                        | Finding disposition                                  |
|-----------------|----------------------------------------------------------------|------------------------------------------------------|
| `Valid`         | Structural check passed (CRC matches, charset correct, etc.)   | Finding emitted; contributes `+5` to confidence score |
| `Invalid`       | Token is structurally broken (bad CRC, wrong header, etc.)     | Suppressed when `suppresses_on_invalid()` is `true`   |
| `Indeterminate` | Cannot determine (too short, wrong prefix, ambiguous)          | Finding always emitted; contributes `0` to confidence  |

The `suppresses_on_invalid()` method on `OfflineValidationSpec` is a per-spec
policy flag. Currently all variants return `true` — invalid verdicts suppress
the finding. The match arm is kept explicit so adding a new variant forces a
compile-time decision (`api.rs`).

---

## Key Types

### `OfflineValidationSpec` (enum, `api.rs`)

The spec enum carried on `RuleSpec.offline_validation`. Each variant encodes a
self-contained check with the per-rule geometry needed to locate
checksum/payload fields. At engine build time, specs are pooled into
`Engine::offline_validation_gates` and referenced by index from
`RuleCompiled::offline_validation` (`rule_repr.rs`).

```rust
pub enum OfflineValidationSpec {
    Crc32Base62 { prefix_skip: u8, payload_len: u8, checksum_len: u8 },
    GithubFinegrainedPat,
    GrafanaServiceAccount,
    AwsAccessKey,
    SentryOrgToken,
    PyPiToken,
    SlackToken,
}
```

**Invariants** (enforced by `assert_valid`, `api.rs`):
- `Crc32Base62`: `payload_len > 0`, `checksum_len > 0`, `checksum_len <= 6`.
- Unit variants: always valid.

### `OfflineVerdict` (enum, `api.rs`)

```rust
pub enum OfflineVerdict { Valid, Invalid, Indeterminate }
```

### `validate` (dispatch function, `offline_validate.rs`)

```rust
pub(crate) fn validate(spec: OfflineValidationSpec, secret: &[u8]) -> OfflineVerdict
```

Top-level dispatch: matches on the spec variant and delegates to the
appropriate validator function. Called by `compute_offline_verdict` in
`window_validate.rs`.

---

## Integration: How Validators Are Invoked

### Pipeline Position

Offline validation is Gate 14 in the window validation pipeline (see
`engine-window-validation.md`):

```
... → [Gate 13] UUID-format quick-reject
      → [Gate 14] Offline structural validation  ← this module
      → [Step 15] Compute confidence score
      → [Gate 16] min_confidence threshold → Finding emitted
```

### Call Chain

1. **`apply_emit_time_policy`** (`window_validate.rs`):
   Calls `compute_offline_verdict()` on the extracted secret bytes.

2. **`compute_offline_verdict`** (`window_validate.rs`):
   - Returns `None` if `parent_step_id != STEP_ROOT` (transform-derived findings
     are not validated).
   - Looks up the rule's `offline_validation` pool index via
     `Engine::offline_validation_gate()`.
   - Calls `offline_validate::validate(spec, secret_bytes)`.

3. **Suppression**: If the verdict is `Invalid` and `spec.suppresses_on_invalid()`
   is `true`, the finding is discarded and `scratch.offline_suppressed` is
   incremented.

4. **Confidence scoring**: If the verdict is `Valid`, the finding receives
    `+5` to its confidence score (`confidence::OFFLINE_VALID`, `api.rs`).
   `Invalid` and `Indeterminate` contribute `0`.

### Scope Restrictions

- **Root-semantic only**: Only findings with `parent_step_id == STEP_ROOT` are
  validated. This includes root-level UTF-16 findings whose own `step_id` is a
  `Utf16Window` decode step — the check uses the *parent* step ID.
- **Transform-derived excluded**: Secrets discovered inside base64-decoded or
  URL-decoded spans skip offline validation because their byte representation
  differs from the original token format.

### Engine Build-Time Pooling

At engine construction (`core.rs`), each rule's
`OfflineValidationSpec` is pushed into `Engine::offline_validation_gates` (a
`Vec<OfflineValidationSpec>`). The rule's `RuleCompiled::offline_validation`
field stores the pool index (or `NO_GATE = u32::MAX` when absent). At scan
time, `Engine::offline_validation_gate(idx)` dereferences the index.

---

## Validator Catalog

### 1. `Crc32Base62` — Generic CRC-32 + Base-62 Checksum

**Function**: `validate_crc32_base62` (`offline_validate.rs`)

**Token layout**: `[prefix_skip bytes][payload_len bytes][checksum_len bytes]`

**What it checks**:
- Token length is at least `prefix_skip + payload_len + checksum_len`.
- The `checksum_len` trailing bytes are valid base-62 characters.
- The base-62-decoded checksum equals `crc32(payload)`.

**Structural properties validated**:
- CRC-32 integrity over the payload region.
- Base-62 charset in the checksum region (`[0-9A-Za-z]`).

**False positives rejected**: Any token where the regex-extracted span has a
payload that does not match its embedded CRC-32. Common with substring matches
that grab adjacent non-token characters.

**Parameters**: `prefix_skip` bytes are skipped before the payload. The CRC
is computed over `payload_len` bytes starting at offset `prefix_skip`.

**Verdict behavior**:
- Non-base-62 checksum bytes → `Indeterminate` (regex may have grabbed a
  wider span than the actual token).
- Length too short → `Indeterminate`.
- CRC match → `Valid`; mismatch → `Invalid`.

---

### 2. `GithubFinegrainedPat` — GitHub Fine-Grained Personal Access Token

**Function**: `validate_github_fine_grained_pat` (`offline_validate.rs`)

**Token format**: `github_pat_<76 body chars><6 char CRC-32 base-62>` (93 bytes total).

**What it checks**:
- Length is at least 93 bytes.
- Starts with `github_pat_`.
- The trailing 6 bytes are valid base-62.
- CRC-32 of the **first 87 bytes** (including the `github_pat_` prefix) matches
  the base-62-decoded checksum.

**Key difference from generic `Crc32Base62`**: The CRC is computed over the
*entire* token prefix (including `github_pat_`), not just the payload after
the prefix.

**Structural properties validated**: CRC-32 integrity, prefix, total length.

**False positives rejected**: Random 93-character strings that happen to match
the `github_pat_` regex but have an invalid checksum.

**Constants** (`offline_validate.rs`):
- `GH_PAT_PREFIX`: `b"github_pat_"` (11 bytes)
- `GH_PAT_TOTAL_LEN`: 93
- `GH_PAT_CHECKSUM_LEN`: 6

---

### 3. `GrafanaServiceAccount` — Grafana Service-Account Token

**Function**: `validate_grafana_service_account` (`offline_validate.rs`)

**Token format**: `glsa_<32 alphanumeric>_<8 hex CRC-32>` (46 bytes total).

**What it checks**:
- Length is at least 46 bytes.
- Starts with `glsa_`.
- Byte at position 37 is `_` (separator between random segment and checksum).
- The trailing 8 bytes are valid hex digits.
- CRC-32 of `glsa_<32 chars>` (37 bytes) matches the hex-decoded checksum.

**Structural properties validated**: CRC-32 integrity (hex-encoded), prefix,
separator position, minimum length.

**False positives rejected**: Tokens with corrupted random segments or
checksum fields.

**Constants** (`offline_validate.rs`):
- `GLSA_PREFIX`: `b"glsa_"` (5 bytes)
- `GLSA_MIN_LEN`: 46
- `GLSA_RANDOM_LEN`: 32
- `GLSA_CHECKSUM_HEX_LEN`: 8

---

### 4. `AwsAccessKey` — AWS Access Key ID

**Function**: `validate_aws_access_key` (`offline_validate.rs`)

**Token format**: `(AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16}` (20 bytes).

**What it checks**:
1. Length is at least 20 bytes (only the first 20 are examined).
2. 4-byte prefix matches a known AWS key type (`AKIA`, `ASIA`, `ABIA`, `ACCA`,
   or `A3T` followed by an uppercase letter or digit).
3. Characters 4–19 are in the AWS base-32 alphabet (`[A-Z2-7]`).
4. The base-32-decoded 16-character suffix encodes a 40-bit account ID that is
   a valid AWS account number (≤ 999,999,999,999, i.e., 12 decimal digits).

**Structural properties validated**:
- Known prefix (validated via single `u32` load + comparison tree for
  branch-free prefix matching, `offline_validate.rs`).
- Base-32 charset compliance.
- Account ID range check on decoded bits.

**False positives rejected**:
- Random 20-character strings starting with `AKIA` but containing lowercase
  letters or digits outside `[2-7]`.
- Keys with structurally impossible account IDs (> 12 decimal digits).

**Account ID extraction** (`decode_aws_account_id`, `offline_validate.rs`):
The 16 base-32 chars encode 80 bits (10 bytes). The account ID occupies bits
1–40 (0-indexed from MSB, skipping the top flag bit). The extraction masks
off the flag bit and packs 40 contiguous bits into a `u64`.

**Verdict behavior**:
- Unknown prefix → `Indeterminate`.
- Invalid base-32 chars → `Invalid`.
- Account ID > 999,999,999,999 → `Invalid`.
- Valid prefix + charset + account ID → `Valid`.

---

### 5. `SentryOrgToken` — Sentry Org Auth Token

**Function**: `validate_sentry_org_token` (`offline_validate.rs`)

**Token format**: `sntrys_<base64-payload>_<43 base64 signature>`.

**What it checks**:
1. Starts with `sntrys_`.
2. Contains a `_` separator (found via `rposition`) between the payload and the
   43-character signature.
3. The 43-byte signature contains only valid base64 data characters (not padding
   or invalid bytes) — verified via branchless OR-accumulation
    (`offline_validate.rs`).
4. The base64 payload decodes successfully and its decoded bytes start with
   `{"iat":` (JSON payload with an `iat` field).

**Structural properties validated**:
- Prefix and separator structure.
- Base64 charset validity of the entire payload (phase 1 branchless scan).
- Decoded payload content prefix (`{"iat":`).

**False positives rejected**:
- Strings matching the `sntrys_` regex pattern but containing non-base64
  characters.
- Tokens whose payload does not decode to JSON with an `iat` field.

**Two-phase decode** (`base64_decoded_starts_with`, `offline_validate.rs`):
- **Phase 1**: Branchless validity scan over ALL input bytes using the
  `v & (v >> 7)` trick to distinguish `0xFF` (invalid) from `0xFE` (padding)
  and valid values (0–63).
- **Phase 2**: Decode only the first `ceil(prefix.len() / 3) * 4` base64 chars
  (12 chars for the 7-byte `{"iat":` prefix) and compare.

**Verdict behavior**:
- Wrong prefix / no separator / signature too short → `Indeterminate`.
- Invalid signature characters → `Invalid`.
- Invalid base64 in payload → `Invalid`.
- Decoded payload does not start with `{"iat":` → `Invalid`.
- Decoded payload too large (> 512 bytes cap) → `Indeterminate`.
- All checks pass → `Valid`.

---

### 6. `PyPiToken` — PyPI Upload Token (Macaroon V2)

**Function**: `validate_pypi_token` (`offline_validate.rs`)

**Token format**: `pypi-<base64url-encoded macaroon body>`.

**What it checks**:
1. Length is at least 21 bytes (`pypi-` + 16 base64url header chars).
2. Starts with `pypi-`.
3. The first 16 base64url characters after the prefix decode to exactly 12 bytes.
4. Those 12 decoded bytes match the known macaroon V2 header for `pypi.org`.

**Expected header** (`PYPI_HEADER`, `offline_validate.rs`):
```text
Offset  Hex   Meaning
0       0x02  Macaroon V2 version
1       0x01  LOCATION field tag
2       0x08  LOCATION length (8 = len("pypi.org"))
3-10    ...   "pypi.org" (8 ASCII bytes)
11      0x02  IDENTIFIER field tag
```

**Structural properties validated**:
- Prefix match.
- Base64url charset compliance (using `BASE64URL_LUT` which maps `-` → 62,
  `_` → 63, no padding sentinel).
- Binary header signature match.

**False positives rejected**:
- Strings starting with `pypi-` but containing non-base64url characters.
- Tokens whose decoded body has a different macaroon version, location, or
  field structure.

**Constants** (`offline_validate.rs`):
- `PYPI_PREFIX`: `b"pypi-"` (5 bytes)
- `PYPI_B64URL_HEADER_CHARS`: 16
- `PYPI_MIN_LEN`: 21

---

### 7. `SlackToken` — Slack API Token

**Function**: `validate_slack_token` (`offline_validate.rs`)

Slack tokens are a family of formats sharing the `xox*-` prefix convention.
The validator dispatches on prefix to seven sub-validators, each enforcing
format-specific segment counts, character classes, and length ranges.

#### Dispatch Table

| Prefix             | Sub-validator                       | Format after prefix                              | Case sensitivity |
|--------------------|-------------------------------------|--------------------------------------------------|------------------|
| `xoxe.xox[bp]-`   | `validate_slack_config_access`      | `{1 digit}-{163–166 upper+digit}`                | insensitive      |
| `xoxb-`            | `validate_slack_xoxb`               | Current: `{d10-13}-{d10-13}-{alnum+hyphen tail}` | sensitive        |
|                    |                                     | Legacy: `{d8-14}-{an18-26}`                      |                  |
| `xoxp-`            | `validate_slack_user_token`         | `{d10-13}-{d10-13}-{d10-13}-{an+hyphen 28-34}`   | sensitive        |
| `xoxe-`            | `validate_slack_xoxe`               | Config refresh: `{1 digit}-{146 upper+digit}`    | insensitive      |
|                    |                                     | User/enterprise: same as `xoxp-`                 |                  |
| `xapp-`            | `validate_slack_xapp`               | `{1 digit}-{upper+digit}-{digits}-{lower+digit}` | insensitive      |
| `xox[os]-`         | `validate_slack_legacy`             | `{d+}-{d+}-{d+}-{hex+}`                          | sensitive        |
| `xox[ar]-`         | `validate_slack_legacy_workspace`   | `(?:{digit}-)?{an8-48}`                          | sensitive        |

**Dispatch ordering**: Compound prefixes (`xoxe.xoxb-`, `xoxe.xoxp-`) are
checked first (10-byte prefix) to avoid misrouting through the simpler `xoxe-`
path (`offline_validate.rs`).

**Structural properties validated** (per sub-format):
- Segment count (split on `-`).
- Per-segment character class (digits, uppercase+digits, lowercase+digits,
  alphanumeric, hex).
- Per-segment length ranges.

**False positives rejected**:
- Strings matching `xox*-` regex patterns but with wrong segment counts or
  character classes (e.g., `xoxb-123-abc` has segments too short for either
  current or legacy bot token formats).

**Verdict behavior**:
- Unknown prefix → `Indeterminate` (forward-compatible with future Slack
  token formats).
- `xoxb-` where neither current nor legacy format matches → `Indeterminate`
  (same forward-compatibility rationale).
- `xoxe-` where first segment is neither 1 digit nor 10–13 digits →
  `Indeterminate`.
- Structural violations within a recognized format → `Invalid`.

#### Sub-Validators

**`validate_slack_config_access`** (`offline_validate.rs`):
Format: `{1 digit}-{163–166 uppercase+digit body}`. Validates the leading
single-digit segment and the body length and character class.

**`validate_slack_xoxb`** (`offline_validate.rs`):
Tries current format first (3+ segments with two 10–13 digit segments and an
alphanumeric+hyphen tail), then falls back to legacy format (2 segments: 8–14
digits, 18–26 alphanumeric). Returns `Indeterminate` if neither matches.

**`validate_slack_user_token`** (`offline_validate.rs`):
Format: three numeric segments (10–13 digits each) followed by an
alphanumeric+hyphen tail (28–34 characters). Also used by `validate_slack_xoxe`
for user/enterprise tokens.

**`validate_slack_xoxe`** (`offline_validate.rs`):
Disambiguates by first segment length: 1 digit → config refresh token (146
uppercase+digit body); 10–13 digits → delegates to `validate_slack_user_token`.

**`validate_slack_xapp`** (`offline_validate.rs`):
Format: 4 segments — single digit, uppercase+digits, digits, lowercase+digits.

**`validate_slack_legacy`** (`offline_validate.rs`):
Format: three digit-only segments followed by a hex segment.

**`validate_slack_legacy_workspace`** (`offline_validate.rs`):
Format: optional leading `{digit}-` followed by 8–48 alphanumeric characters.

---

## Branchless Decode Strategy

All four lookup tables share a common sentinel convention to enable branchless
decode loops:

| Table             | Location                     | Valid range | Invalid | Padding |
|-------------------|------------------------------|-------------|---------|---------|
| `BASE62_LUT`      | `offline_validate.rs`        | 0–61        | `0xFF`  | —       |
| `HEX_LUT`         | `offline_validate.rs`        | 0–15        | `0xFF`  | —       |
| `BASE64_LUT`      | `offline_validate.rs`        | 0–63        | `0xFF`  | `0xFE`  |
| `BASE64URL_LUT`   | `offline_validate.rs`        | 0–63        | `0xFF`  | —       |

**Convention**: Valid values never set bit 7. Invalid bytes map to `0xFF`
(bit 7 set). Base64 padding (`=`) maps to `0xFE` (bit 7 set, bit 0 clear).

**Decode loop pattern**: OR-accumulate lookup results into a single `invalid`
flag and defer the validity branch until after the loop. This eliminates
per-character branches, giving the CPU a straight-line body that the
out-of-order engine can pipeline without misprediction stalls.

```rust
// Example: base62_decode_u32 (offline_validate.rs)
let mut acc: u64 = 0;
let mut invalid: u8 = 0;
for &b in bytes {
    let v = BASE62_LUT[b as usize];
    invalid |= v;
    acc = acc * 62 + v as u64;
}
if invalid & 0x80 != 0 { return None; }
```

On AArch64, the loop body compiles to `ldrb + orr + madd` (3 instructions, 0
branches per character).

**`BASE64_LUT` sentinel trick** (`base64_decoded_starts_with`): The `0xFE`/`0xFF`
distinction enables the `v & (v >> 7)` test:
- `0xFF & (0xFF >> 7) = 0xFF & 1 = 1` → invalid
- `0xFE & (0xFE >> 7) = 0xFE & 1 = 0` → padding (acceptable)
- `0–63 & 0 = 0` → valid

---

## Performance

### Allocation-Free Hot Path

All validators use stack-local buffers for decoding:
- Base-62 decode uses a `u64` accumulator.
- Hex decode uses a `u32` accumulator.
- AWS base-32 decode uses `[u8; 10]`.
- PyPI base64url decode uses `[u8; 12]`.
- Sentry base64 decode uses inline `u32` accumulator with early prefix check.
- Slack validators use `splitn_stack::<N>` (`offline_validate.rs`), a
  stack-local array-based split that avoids `Vec` allocation.

### Bench Hooks

Feature-gated (`bench`) public functions are provided for benchmarking
individual validators without going through the dispatch layer:
- `bench_offline_validate_aws_access_key` (`offline_validate.rs`)
- `bench_offline_validate_sentry_org_token` (`offline_validate.rs`)
- `bench_offline_validate_pypi_token` (`offline_validate.rs`)
- `bench_offline_validate_slack_token` (`offline_validate.rs`)

---

## Adding a New Validator

### Step 1: Define the Spec Variant

Add a new variant to `OfflineValidationSpec` in `api.rs`. If the check
requires per-rule parameters, add fields to the variant; otherwise use a unit
variant.

### Step 2: Update `assert_valid`

Add invariant checks for the new variant in `OfflineValidationSpec::assert_valid`
(`api.rs`). At minimum, ensure the variant arm exists (the match is
exhaustive).

### Step 3: Update `suppresses_on_invalid`

Add the variant to `OfflineValidationSpec::suppresses_on_invalid`
(`api.rs`). Decide whether an `Invalid` verdict should suppress the
finding or keep it for manual review.

### Step 4: Update `encode_policy`

Add the variant to `OfflineValidationSpec::encode_policy` (`api.rs`)
with a unique tag byte. This ensures the policy hash changes when the
validator is added, invalidating cached scan results.

### Step 5: Implement the Validator Function

Add a `validate_<name>(secret: &[u8]) -> OfflineVerdict` function in
`offline_validate.rs`. Follow these conventions:
- Return `Indeterminate` for ambiguous cases (too short, wrong prefix).
- Return `Invalid` only with positive proof of structural failure.
- Use stack-local buffers — no heap allocation.
- Use branchless decode loops where applicable.

### Step 6: Wire the Dispatch

Add a match arm to `validate()` (`offline_validate.rs`) that calls the
new validator.

### Step 7: Add Tests

Add unit tests (and optionally `proptest` round-trip tests) to the `tests`
and `proptest_offline` modules at the bottom of `offline_validate.rs`.

### Step 8: Wire Rules

Set `offline_validation: Some(OfflineValidationSpec::NewVariant)` on the
`RuleSpec` for rules that should use the new validator (typically in the YAML
rule definitions parsed by `rules/yaml.rs`).

---

## Testing

### Unit Tests (`offline_validate.rs`)

Comprehensive test coverage for every validator:

| Test group                        | What is tested                                                 |
|-----------------------------------|----------------------------------------------------------------|
| `base62_encode_decode_round_trip` | Base-62 codec round-trip for representative values             |
| `base62_decode_invalid_char`      | Invalid character rejection                                    |
| `base62_decode_overflow`          | `u32` overflow rejection                                       |
| `hex_decode_valid`                | Hex decode correctness (0, `u32::MAX`, `0xDEADBEEF`)          |
| `hex_decode_wrong_length`         | Rejects inputs ≠ 8 bytes                                       |
| `hex_decode_invalid_char`         | Non-hex character rejection                                    |
| `base64_decode_*`                 | Base64 decode with/without padding, invalid chars              |
| `crc32_base62_*`                  | Valid, invalid checksum, too-short token                       |
| `github_pat_*`                    | Valid, invalid checksum, too short, wrong prefix               |
| `grafana_*`                       | Valid, invalid checksum, too short                             |
| `aws_*`                           | Valid charset, invalid charset, too short, unknown prefix, A3T |
| `sentry_*`                        | Valid structure, invalid payload, literal edge cases            |
| `pypi_*`                          | Valid token, invalid body char, literal edge cases              |
| `slack_token_cases`               | Table-driven tests for all Slack sub-formats                   |

### Property-Based Tests (`offline_validate.rs`, feature `stdx-proptest`)

- `crc32_base62_roundtrip_valid`: Random 10-byte payloads always `Valid`.
- `github_pat_roundtrip_valid`: Random 76-byte bodies always `Valid`.
- `grafana_roundtrip_valid`: Random 32-char alphanumeric segments always `Valid`.
- `base62_roundtrip`: Any `u32` value round-trips through encode/decode.

### Integration Tests (`engine/tests.rs`)

End-to-end tests that verify offline validation interacts correctly with the
window validation pipeline:
- `offline_validation_suppresses_invalid_crc_token`
- `offline_validation_keeps_valid_crc_token`
- `offline_validation_does_not_affect_rules_without_gate`
- `offline_validation_indeterminate_keeps_finding`
- `offline_validation_mixed_rules_selective_suppression`
- `offline_validation_suppresses_invalid_root_finding`
- `offline_validation_keeps_valid_root_finding`
- `offline_validation_does_not_suppress_non_root_findings`
- `offline_validation_suppresses_invalid_utf16_root_finding`
- `offline_validation_keeps_valid_utf16_root_finding`
- `offline_validation_utf16_root_counts_suppressed`
- `offline_validation_suppresses_invalid_utf16be_root_finding`

---

## Source of Truth

| Component                          | File                                                    |
|------------------------------------|---------------------------------------------------------|
| `OfflineValidationSpec` enum       | `crates/scanner-engine/src/api.rs`                      |
| `OfflineValidationSpec::assert_valid` | `crates/scanner-engine/src/api.rs`                   |
| `suppresses_on_invalid`            | `crates/scanner-engine/src/api.rs`                      |
| `OfflineVerdict` enum              | `crates/scanner-engine/src/api.rs`                      |
| `confidence::OFFLINE_VALID`        | `crates/scanner-engine/src/api.rs`                      |
| `encode_policy` (spec)             | `crates/scanner-engine/src/api.rs`                      |
| `validate` (dispatch)              | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `BASE62_LUT`                       | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `base62_decode_u32`                | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_crc32_base62`            | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_github_fine_grained_pat` | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_grafana_service_account` | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `HEX_LUT`                          | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `hex_decode_u32`                   | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_aws_access_key`          | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `decode_aws_account_id`            | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_sentry_org_token`        | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `BASE64_LUT`                       | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `BASE64URL_LUT`                    | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `base64_decoded_starts_with`       | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_pypi_token`              | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_slack_token`             | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_slack_config_access`     | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_slack_xapp`              | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_slack_xoxb`              | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_slack_user_token`        | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_slack_xoxe`              | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_slack_legacy`            | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `validate_slack_legacy_workspace`  | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `splitn_stack`                     | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `all_bytes`                        | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| `compute_offline_verdict`          | `crates/scanner-engine/src/engine/window_validate.rs`   |
| `apply_emit_time_policy` (offline) | `crates/scanner-engine/src/engine/window_validate.rs`   |
| `offline_validation_gate` (pool)   | `crates/scanner-engine/src/engine/core.rs`              |
| `offline_validation_gates` (vec)   | `crates/scanner-engine/src/engine/core.rs`              |
| `RuleCompiled::offline_validation` | `crates/scanner-engine/src/engine/rule_repr.rs`         |
| `scratch.offline_suppressed`       | `crates/scanner-engine/src/engine/scratch.rs`           |
| Unit tests                         | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| Property-based tests               | `crates/scanner-engine/src/engine/offline_validate.rs`  |
| Integration tests                  | `crates/scanner-engine/src/engine/tests.rs`             |
