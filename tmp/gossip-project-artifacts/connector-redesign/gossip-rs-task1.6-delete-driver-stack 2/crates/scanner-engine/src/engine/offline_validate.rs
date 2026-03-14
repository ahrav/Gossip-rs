//! Offline structural validation for extracted secrets.
//!
//! Each validator runs a deterministic, network-free check on secret bytes
//! already extracted by the regex engine. The goal is to reject structurally
//! invalid tokens (likely false positives) before they reach the output sink.
//!
//! ## Supported token types
//!
//! | Variant                  | Format sketch                         | Validation strategy                    |
//! |--------------------------|---------------------------------------|----------------------------------------|
//! | CRC-32 + base-62         | `<prefix><payload><base62(crc32)>`    | Recompute CRC, compare                 |
//! | GitHub fine-grained PAT  | `github_pat_<76 body><6 base62 CRC>`  | CRC over first 87 bytes                |
//! | Grafana service-account  | `glsa_<32 alnum>_<8 hex CRC>`         | CRC over `glsa_<32>`                   |
//! | AWS access key ID        | `(AKIA\|ASIA\|...)[A-Z2-7]{16}`      | Base-32 decode, account-ID range check |
//! | Sentry org-auth-token    | `sntrys_<b64 payload>_<43 b64 sig>`   | Base64 decode, `{"iat":` prefix check  |
//! | PyPI upload token        | `pypi-<b64url macaroon V2 body>`      | Base64url decode, 12-byte header match |
//! | Slack API token          | `xox[bpeos…]-<segments>`              | Prefix dispatch, segment count/charset |
//!
//! ## Verdict hierarchy
//!
//! Every validator returns one of three outcomes:
//!
//! - [`Valid`](OfflineVerdict::Valid) — structural check passed; finding is
//!   likely real.
//! - [`Invalid`](OfflineVerdict::Invalid) — token is structurally broken (bad
//!   CRC, invalid charset after prefix match, etc.); safe to suppress.
//! - [`Indeterminate`](OfflineVerdict::Indeterminate) — cannot tell (too
//!   short, wrong prefix, ambiguous); **do not suppress**.
//!
//! The asymmetry is intentional: `Invalid` requires positive proof of
//! structural failure; anything uncertain stays `Indeterminate`.
//!
//! ## Scope
//!
//! Offline validation runs **inline at emission time** in `window_validate.rs`
//! for root-semantic findings only (parent `step_id == STEP_ROOT`). This
//! includes UTF-16 root findings whose parent is `STEP_ROOT` even though
//! their own `step_id` is a `Utf16Window` decode step. Transform-derived
//! findings (e.g. secrets discovered inside a base64-decoded span) are not
//! validated because their parent step_id is not `STEP_ROOT`. This means a
//! rule with both transform decoding and `offline_validation` will only
//! validate direct (root) matches.
//!
//! ## Design constraints
//!
//! - **No heap allocation.** Decode buffers are stack-local (`[u8; N]`) so
//!   the hot path stays allocation-free.
//! - **Conservative verdicts.** When a token is too short or structurally
//!   ambiguous, return `Indeterminate` rather than `Invalid` to avoid
//!   suppressing legitimate findings.
//! - **No regex or I/O.** Validators work on the already-extracted `&[u8]`
//!   slice; they must not compile regexes, open files, or make network calls.
//!
//! ## Branchless decode strategy
//!
//! All four lookup tables ([`BASE62_LUT`], [`HEX_LUT`], [`BASE64_LUT`],
//! [`BASE64URL_LUT`]) share a common sentinel convention:
//!
//! - Valid values occupy the low bits (0–61 for base-62, 0–15 for hex,
//!   0–63 for base64) and **never** set bit 7.
//! - Invalid bytes map to `0xFF` (bit 7 set).
//! - Base64 padding (`=`) maps to `0xFE` (bit 7 set, bit 0 clear).
//! - [`BASE64URL_LUT`] omits the padding sentinel (`0xFE`) entirely because
//!   its sole caller (PyPI macaroon tokens) never encounters `=` padding.
//!
//! Decode loops exploit this by OR-accumulating lookup results into a
//! single `invalid` flag and deferring the validity branch until after
//! the loop. This eliminates per-character branches, giving the CPU a
//! straight-line body (on AArch64: `ldrb + orr + madd` / `lsl + orr`) that the
//! out-of-order engine can pipeline without misprediction stalls.

use crate::api::{OfflineValidationSpec, OfflineVerdict};

/// Dispatch an offline validation check for the given spec and secret bytes.
///
/// Called by the inline emission-time gate when a rule has an `offline_validation` gate.
/// Returns [`OfflineVerdict::Valid`], [`Invalid`](OfflineVerdict::Invalid),
/// or [`Indeterminate`](OfflineVerdict::Indeterminate).
pub(crate) fn validate(spec: OfflineValidationSpec, secret: &[u8]) -> OfflineVerdict {
    match spec {
        OfflineValidationSpec::Crc32Base62 {
            prefix_skip,
            payload_len,
            checksum_len,
        } => validate_crc32_base62(secret, prefix_skip, payload_len, checksum_len),
        OfflineValidationSpec::GithubFinegrainedPat => validate_github_fine_grained_pat(secret),
        OfflineValidationSpec::GrafanaServiceAccount => validate_grafana_service_account(secret),
        OfflineValidationSpec::AwsAccessKey => validate_aws_access_key(secret),
        OfflineValidationSpec::SentryOrgToken => validate_sentry_org_token(secret),
        OfflineValidationSpec::PyPiToken => validate_pypi_token(secret),
        OfflineValidationSpec::SlackToken => validate_slack_token(secret),
    }
}

// ---------------------------------------------------------------------------
// Base-62 helpers
// ---------------------------------------------------------------------------

/// Base-62 decode table (256 entries, one per byte value).
///
/// Valid entries: `'0'–'9'` → 0–9, `'A'–'Z'` → 10–35, `'a'–'z'` → 36–61.
/// All other entries are `0xFF` (bit 7 set), the invalid sentinel.
const BASE62_LUT: [u8; 256] = {
    let mut lut = [0xFFu8; 256];
    let mut i: u16 = 0;
    while i < 256 {
        let b = i as u8;
        if b >= b'0' && b <= b'9' {
            lut[i as usize] = b - b'0';
        } else if b >= b'A' && b <= b'Z' {
            lut[i as usize] = b - b'A' + 10;
        } else if b >= b'a' && b <= b'z' {
            lut[i as usize] = b - b'a' + 36;
        }
        i += 1;
    }
    lut
};

/// Decode a base-62 byte string into a `u32`, returning `None` on overflow
/// or invalid characters.
///
/// Uses a `u64` accumulator with deferred validity to eliminate all
/// per-character branches. On AArch64, the loop body compiles to
/// `ldrb + orr + madd` (3 instructions, 0 branches per character).
///
/// **Correctness argument:**
/// - Valid LUT values (0–61) never set bit 7; the sentinel `0xFF` does.
///   OR-accumulating into `invalid` captures any bad byte without
///   short-circuiting the loop.
/// - Garbage accumulated from invalid digits is discarded by the final
///   `invalid` check — the accumulator is never read on the error path.
/// - For the inputs in this module (at most 6 chars), `u64` cannot overflow:
///   `62^6 = 56_800_235_584 < u64::MAX`. Callers passing more than ~10
///   characters should be aware of potential `u64` wrapping.
///   The `u32::try_from` at the end rejects values above `u32::MAX`.
#[inline]
fn base62_decode_u32(bytes: &[u8]) -> Option<u32> {
    let mut acc: u64 = 0;
    let mut invalid: u8 = 0;
    for &b in bytes {
        let v = BASE62_LUT[b as usize];
        invalid |= v;
        acc = acc * 62 + v as u64;
    }
    if invalid & 0x80 != 0 {
        return None;
    }
    u32::try_from(acc).ok()
}

// ---------------------------------------------------------------------------
// CRC-32 + Base-62 (generic parameterised validator)
// ---------------------------------------------------------------------------

/// Validate a token using CRC-32 with base-62-encoded checksum.
///
/// Layout: `[prefix_skip bytes][payload_len bytes][checksum_len bytes]`.
/// The checksum is the base-62 encoding of `crc32(payload)`.
///
/// Returns `Indeterminate` (not `Invalid`) when the checksum contains
/// non-base-62 characters, because the regex match may have grabbed a
/// wider span than the actual token.
fn validate_crc32_base62(
    secret: &[u8],
    prefix_skip: u8,
    payload_len: u8,
    checksum_len: u8,
) -> OfflineVerdict {
    let skip = prefix_skip as usize;
    let plen = payload_len as usize;
    let clen = checksum_len as usize;
    let required = skip + plen + clen;

    if secret.len() < required {
        return OfflineVerdict::Indeterminate;
    }

    let payload = &secret[skip..skip + plen];
    let checksum_bytes = &secret[skip + plen..skip + plen + clen];

    let actual_crc = crc32fast::hash(payload);

    let decoded_crc = match base62_decode_u32(checksum_bytes) {
        Some(v) => v,
        None => return OfflineVerdict::Indeterminate,
    };

    if actual_crc == decoded_crc {
        OfflineVerdict::Valid
    } else {
        OfflineVerdict::Invalid
    }
}

// ---------------------------------------------------------------------------
// GitHub fine-grained PAT
// ---------------------------------------------------------------------------

/// Literal prefix of a GitHub fine-grained personal access token.
const GH_PAT_PREFIX: &[u8] = b"github_pat_";
/// Total length of a GitHub fine-grained PAT: `github_pat_` (11) + 76 body + 6 checksum = 93.
const GH_PAT_TOTAL_LEN: usize = 93;
/// Trailing CRC-32 checksum encoded as 6 base-62 characters.
const GH_PAT_CHECKSUM_LEN: usize = 6;

/// Validate a GitHub fine-grained personal access token.
///
/// Format: `github_pat_<76 body chars><6 char CRC-32 base-62>` (93 bytes total).
/// The CRC-32 is computed over the first 87 bytes (everything before the checksum),
/// which **includes the `github_pat_` prefix** — unlike [`validate_crc32_base62`]
/// where the prefix is skipped before hashing.
fn validate_github_fine_grained_pat(secret: &[u8]) -> OfflineVerdict {
    if secret.len() < GH_PAT_TOTAL_LEN {
        return OfflineVerdict::Indeterminate;
    }

    if !secret.starts_with(GH_PAT_PREFIX) {
        return OfflineVerdict::Indeterminate;
    }

    let data = &secret[..GH_PAT_TOTAL_LEN - GH_PAT_CHECKSUM_LEN];
    let checksum_bytes = &secret[GH_PAT_TOTAL_LEN - GH_PAT_CHECKSUM_LEN..GH_PAT_TOTAL_LEN];

    let actual_crc = crc32fast::hash(data);
    let decoded_crc = match base62_decode_u32(checksum_bytes) {
        Some(v) => v,
        None => return OfflineVerdict::Indeterminate,
    };

    if actual_crc == decoded_crc {
        OfflineVerdict::Valid
    } else {
        OfflineVerdict::Invalid
    }
}

// ---------------------------------------------------------------------------
// Grafana service-account token
// ---------------------------------------------------------------------------

/// Literal prefix of a Grafana service-account token.
const GLSA_PREFIX: &[u8] = b"glsa_";
/// Minimum length: `glsa_` (5) + 32 random + `_` (1) + 8 hex = 46.
const GLSA_MIN_LEN: usize = 46;
/// Length of the alphanumeric random segment between the prefix and separator.
const GLSA_RANDOM_LEN: usize = 32;
/// CRC-32 encoded as 8 lowercase hex characters.
const GLSA_CHECKSUM_HEX_LEN: usize = 8;

/// Validate a Grafana service-account token.
///
/// Format: `glsa_<32 alphanumeric>_<8 hex CRC-32>`.
/// The CRC-32 is computed over `glsa_<32 chars>` (37 bytes) and hex-encoded
/// in lowercase in the trailing 8 characters.
fn validate_grafana_service_account(secret: &[u8]) -> OfflineVerdict {
    if secret.len() < GLSA_MIN_LEN {
        return OfflineVerdict::Indeterminate;
    }

    if !secret.starts_with(GLSA_PREFIX) {
        return OfflineVerdict::Indeterminate;
    }

    let sep_pos = GLSA_PREFIX.len() + GLSA_RANDOM_LEN;
    if secret[sep_pos] != b'_' {
        return OfflineVerdict::Indeterminate;
    }

    // Data over which CRC is computed: `glsa_<32 chars>`.
    let data = &secret[..sep_pos];
    let hex_bytes = &secret[sep_pos + 1..sep_pos + 1 + GLSA_CHECKSUM_HEX_LEN];

    let actual_crc = crc32fast::hash(data);
    let decoded_crc = match hex_decode_u32(hex_bytes) {
        Some(v) => v,
        None => return OfflineVerdict::Indeterminate,
    };

    if actual_crc == decoded_crc {
        OfflineVerdict::Valid
    } else {
        OfflineVerdict::Invalid
    }
}

/// Hex decode table (256 entries, one per byte value).
///
/// Valid entries: `'0'–'9'` → 0–9, `'a'–'f'` / `'A'–'F'` → 10–15.
/// All other entries are `0xFF` (bit 7 set), the invalid sentinel.
const HEX_LUT: [u8; 256] = {
    let mut lut = [0xFFu8; 256];
    let mut i: u16 = 0;
    while i < 256 {
        let b = i as u8;
        if b >= b'0' && b <= b'9' {
            lut[i as usize] = b - b'0';
        } else if b >= b'a' && b <= b'f' {
            lut[i as usize] = b - b'a' + 10;
        } else if b >= b'A' && b <= b'F' {
            lut[i as usize] = b - b'A' + 10;
        }
        i += 1;
    }
    lut
};

/// Decode an **exactly 8-byte** hex string (case-insensitive) into a `u32`.
///
/// Same deferred-validity pattern as [`base62_decode_u32`]: valid nibbles
/// (0–15) never set bit 7, the sentinel `0xFF` does. 8 hex digits map
/// 1:1 to 32 bits, so overflow is impossible (`0xFFFF_FFFF = u32::MAX`).
///
/// Returns `None` if the input is not exactly 8 bytes or contains
/// non-hex characters.
#[inline]
fn hex_decode_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.len() != 8 {
        return None;
    }
    let mut acc: u32 = 0;
    let mut invalid: u8 = 0;
    for &b in bytes {
        let nibble = HEX_LUT[b as usize];
        invalid |= nibble;
        acc = (acc << 4) | nibble as u32;
    }
    if invalid & 0x80 != 0 {
        return None;
    }
    Some(acc)
}

// ---------------------------------------------------------------------------
// AWS access key ID
// ---------------------------------------------------------------------------

/// Fixed length of an AWS access key ID (4-byte prefix + 16-byte base-32 suffix).
const AWS_KEY_LEN: usize = 20;

/// Validate an AWS access key ID.
///
/// Format: `(AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16}` (20 bytes).
///
/// AWS key IDs encode an account number in a base-32–like scheme. This
/// validator checks:
/// 1. Length is at least 20 bytes (only the first 20 are examined).
/// 2. Prefix matches a known type.
/// 3. Characters 4–19 are in `[A-Z2-7]` (the AWS base-32 alphabet).
/// 4. The decoded 10-byte suffix encodes a 40-bit account ID in the
///    expected range (≤ 999_999_999_999, i.e., 12 decimal digits).
fn validate_aws_access_key(secret: &[u8]) -> OfflineVerdict {
    if secret.len() < AWS_KEY_LEN {
        return OfflineVerdict::Indeterminate;
    }

    let key = &secret[..AWS_KEY_LEN];

    // Validate known prefix with a single u32 load + comparison tree.
    // This avoids 4 separate `starts_with` calls that each reload key[0..4].
    let prefix_word = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
    const PREFIX_AKIA: u32 = u32::from_le_bytes(*b"AKIA");
    const PREFIX_ASIA: u32 = u32::from_le_bytes(*b"ASIA");
    const PREFIX_ABIA: u32 = u32::from_le_bytes(*b"ABIA");
    const PREFIX_ACCA: u32 = u32::from_le_bytes(*b"ACCA");

    let valid_prefix = matches!(
        prefix_word,
        PREFIX_AKIA | PREFIX_ASIA | PREFIX_ABIA | PREFIX_ACCA
    ) || (key[0] == b'A'
        && key[1] == b'3'
        && key[2] == b'T'
        && (key[3].is_ascii_uppercase() || key[3].is_ascii_digit()));

    if !valid_prefix {
        return OfflineVerdict::Indeterminate;
    }

    // Decode the base-32 suffix to extract the embedded account ID. Invalid
    // charset bytes are caught by `decode_aws_account_id` which returns `None`
    // for any byte outside `[A-Z2-7]`.
    let suffix = &key[4..];

    // AWS encodes a 40-bit account number in bits [1..41] of the 80-bit decoded
    // value (16 base-32 chars = 80 bits). The account ID must be a valid AWS
    // account number (≤ 999_999_999_999).
    match decode_aws_account_id(suffix) {
        Some(id) if id <= 999_999_999_999 => OfflineVerdict::Valid,
        Some(_) => OfflineVerdict::Invalid,
        None => OfflineVerdict::Invalid,
    }
}

/// Decode a 16-char AWS base-32 suffix into the embedded 40-bit account ID.
///
/// The 16 base-32 characters encode 80 bits (10 bytes). The account ID
/// occupies bits 1–40 (0-indexed from MSB, skipping the top flag bit),
/// spanning decoded bytes 0–5.
///
/// ```text
/// Byte:   [  0  ] [  1  ] [  2  ] [  3  ] [  4  ] [  5  ] ...
/// Bits:   F AAAAAAA AAAAAAAA AAAAAAAA AAAAAAAA AAAAAAAA A-------
///         ^                                              ^
///         bit 0 (flag, skipped)                          bit 41+
/// ```
///
/// The extraction `(decoded[0] & 0x7F) << 33 | ... | decoded[5] >> 7`
/// masks off the flag bit and packs 40 contiguous bits into a `u64`.
#[inline]
fn decode_aws_account_id(suffix: &[u8]) -> Option<u64> {
    if suffix.len() != 16 {
        return None;
    }

    // Decode base-32 chars into a single 80-bit value spread across 10 bytes.
    let mut decoded = [0u8; 10];
    let mut bit_buf: u64 = 0;
    let mut bits_in_buf: u32 = 0;
    let mut out_idx = 0;

    for &b in suffix {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u64,
            b'2'..=b'7' => (b - b'2') as u64 + 26,
            _ => return None,
        };
        bit_buf = (bit_buf << 5) | val;
        bits_in_buf += 5;

        while bits_in_buf >= 8 {
            bits_in_buf -= 8;
            decoded[out_idx] = (bit_buf >> bits_in_buf) as u8;
            bit_buf &= (1u64 << bits_in_buf) - 1;
            out_idx += 1;
        }
    }
    debug_assert_eq!(out_idx, decoded.len());

    // Account ID is in bits [1..41] from the MSB of the 80-bit value.
    // In byte terms: skip bit 0 of decoded[0], then take 40 bits.
    let raw_40 = ((decoded[0] as u64 & 0x7F) << 33)
        | ((decoded[1] as u64) << 25)
        | ((decoded[2] as u64) << 17)
        | ((decoded[3] as u64) << 9)
        | ((decoded[4] as u64) << 1)
        | ((decoded[5] as u64) >> 7);

    Some(raw_40)
}

// ---------------------------------------------------------------------------
// Sentry org-auth-token
// ---------------------------------------------------------------------------

/// Literal prefix of a Sentry org-auth-token.
const SENTRY_PREFIX: &[u8] = b"sntrys_";

/// Validate a Sentry org-auth-token.
///
/// Format: `sntrys_<base64-payload>_<43 base64 signature>`.
///
/// Validation:
/// 1. Starts with `sntrys_`.
/// 2. Contains a `_` separator between the payload and the 43-char signature.
/// 3. The base64 payload decodes successfully.
/// 4. The decoded payload starts with `{"iat":` (JSON with `iat` field).
fn validate_sentry_org_token(secret: &[u8]) -> OfflineVerdict {
    if !secret.starts_with(SENTRY_PREFIX) {
        return OfflineVerdict::Indeterminate;
    }

    let after_prefix = &secret[SENTRY_PREFIX.len()..];

    // Find the last `_` separator — everything after it is the 43-char signature.
    let sep_pos = match after_prefix.iter().rposition(|&b| b == b'_') {
        Some(p) => p,
        None => return OfflineVerdict::Indeterminate,
    };

    let sig_part = &after_prefix[sep_pos + 1..];
    if sig_part.len() < 43 {
        return OfflineVerdict::Indeterminate;
    }

    // Branchless signature validation: OR-accumulate `LUT[b] & 0xC0` over
    // 43 bytes. Valid base64 values (0–63) have bits 6–7 clear; both 0xFF
    // (invalid) and 0xFE (padding) have at least one of those bits set.
    // A non-zero result means at least one byte was not a data character.
    let sig_bytes = &sig_part[..43];
    let mut sig_invalid: u8 = 0;
    for &b in sig_bytes {
        sig_invalid |= BASE64_LUT[b as usize] & 0xC0;
    }
    if sig_invalid != 0 {
        return OfflineVerdict::Invalid;
    }

    // The payload is between the prefix and the last `_`.
    let payload_b64 = &after_prefix[..sep_pos];
    if payload_b64.is_empty() {
        return OfflineVerdict::Indeterminate;
    }

    // Two-phase payload check: branchless validity scan over all bytes,
    // then decode only the first ~12 base64 chars to match `{"iat":`.
    // The 512-byte decoded cap returns Indeterminate for oversized payloads.
    match base64_decoded_starts_with(payload_b64, b"{\"iat\":", 512) {
        Ok(true) => OfflineVerdict::Valid,
        Ok(false) => OfflineVerdict::Invalid,
        Err(Base64DecodeError::InvalidChar) => OfflineVerdict::Invalid,
        Err(Base64DecodeError::OutputTooSmall) => OfflineVerdict::Indeterminate,
    }
}

/// Base64 decode table (256 entries, one per byte value).
///
/// Valid entries: `'A'–'Z'` → 0–25, `'a'–'z'` → 26–51, `'0'–'9'` → 52–61,
/// `'+'` → 62, `'/'` → 63. Padding `'='` maps to `0xFE` (bit 7 set,
/// bit 0 clear). All other entries are `0xFF` (bits 7 and 0 both set).
///
/// The `0xFE`/`0xFF` distinction enables the `v & (v >> 7)` trick in
/// [`base64_decoded_starts_with`]: `0xFF & 1 = 1` (invalid), `0xFE & 1 = 0`
/// (padding, acceptable), `0–63 & 0 = 0` (valid).
const BASE64_LUT: [u8; 256] = {
    let mut lut = [0xFFu8; 256];
    let mut i: u16 = 0;
    while i < 256 {
        let b = i as u8;
        if b >= b'A' && b <= b'Z' {
            lut[i as usize] = b - b'A';
        } else if b >= b'a' && b <= b'z' {
            lut[i as usize] = b - b'a' + 26;
        } else if b >= b'0' && b <= b'9' {
            lut[i as usize] = b - b'0' + 52;
        } else if b == b'+' {
            lut[i as usize] = 62;
        } else if b == b'/' {
            lut[i as usize] = 63;
        } else if b == b'=' {
            lut[i as usize] = 0xFE; // padding sentinel
        }
        i += 1;
    }
    lut
};

/// Base64url decode table (256 entries, one per byte value).
///
/// Variant of [`BASE64_LUT`] for the URL-safe alphabet (RFC 4648 §5):
/// `'-'` → 62 (instead of `'+'`), `'_'` → 63 (instead of `'/'`).
/// No padding sentinel — callers (PyPI macaroon tokens) never encounter `=`.
///
/// Valid values (0–63) never set bit 7; the invalid sentinel `0xFF` does.
/// Decode loops use `invalid |= v` to defer the validity branch.
const BASE64URL_LUT: [u8; 256] = {
    let mut lut = [0xFFu8; 256];
    let mut i: u16 = 0;
    while i < 256 {
        let b = i as u8;
        if b >= b'A' && b <= b'Z' {
            lut[i as usize] = b - b'A';
        } else if b >= b'a' && b <= b'z' {
            lut[i as usize] = b - b'a' + 26;
        } else if b >= b'0' && b <= b'9' {
            lut[i as usize] = b - b'0' + 52;
        } else if b == b'-' {
            lut[i as usize] = 62;
        } else if b == b'_' {
            lut[i as usize] = 63;
        }
        i += 1;
    }
    lut
};

/// Reasons a base64-prefix check can fail.
///
/// The Sentry validator maps these to different verdicts:
/// `InvalidChar` → [`OfflineVerdict::Invalid`] (structurally broken),
/// `OutputTooSmall` → [`OfflineVerdict::Indeterminate`] (can't tell).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Base64DecodeError {
    /// Input contains a byte outside the base64 alphabet (not `[A-Za-z0-9+/=]`).
    InvalidChar,
    /// Estimated decoded size exceeds the caller-supplied cap.
    OutputTooSmall,
}

/// Validate base64 input and check whether decoded bytes start with `prefix`.
///
/// Two-phase design for better ILP:
/// - **Phase 1:** Branchless scan of ALL input bytes for validity. Each byte
///   is looked up in `BASE64_LUT`; the `v & (v >> 7)` trick detects 0xFF
///   (invalid) without flagging 0xFE (padding): `0xFF & 1 = 1`, `0xFE & 1 = 0`,
///   valid 0–63: `v >> 7 = 0`.
/// - **Phase 2:** Decode only the first `ceil(prefix.len() / 3) * 4` base64
///   chars and compare decoded bytes against `prefix`.
#[inline]
fn base64_decoded_starts_with(
    input: &[u8],
    prefix: &[u8],
    max_decoded_bytes: usize,
) -> Result<bool, Base64DecodeError> {
    let max_decoded = input.len() * 3 / 4;
    if max_decoded > max_decoded_bytes {
        return Err(Base64DecodeError::OutputTooSmall);
    }

    // Phase 1: branchless validity scan over ALL input bytes.
    // On AArch64 the loop body compiles to ldrb + ldrb + lsr + and + orr
    // — 0 branches per byte.
    let mut any_invalid: u8 = 0;
    for &b in input {
        let v = BASE64_LUT[b as usize];
        // 0xFF → 0xFF & (0xFF >> 7) = 0xFF & 1 = 1 (invalid)
        // 0xFE → 0xFE & (0xFE >> 7) = 0xFE & 1 = 0 (padding, ok)
        // 0–63 → v & 0 = 0 (valid)
        any_invalid |= v & (v >> 7);
    }
    if any_invalid != 0 {
        return Err(Base64DecodeError::InvalidChar);
    }

    // Phase 2: decode only enough base64 chars to cover the prefix.
    // Each group of 4 base64 chars produces 3 decoded bytes, so we need
    // ceil(prefix_len / 3) * 4 input chars. For `{"iat":` (7 bytes):
    // ceil(7/3) * 4 = 12 chars — decoding 12 chars yields 9 bytes ≥ 7.
    if prefix.is_empty() {
        return Ok(true);
    }

    let decode_input_len = prefix.len().div_ceil(3) * 4;
    let decode_slice = if decode_input_len < input.len() {
        &input[..decode_input_len]
    } else {
        input
    };

    let mut buf: u32 = 0;
    let mut buf_bits: u32 = 0;
    let mut prefix_idx: usize = 0;

    for &b in decode_slice {
        let v = BASE64_LUT[b as usize];
        if v >= 0xFE {
            continue; // padding — already validated in phase 1
        }
        buf = (buf << 6) | v as u32;
        buf_bits += 6;

        while buf_bits >= 8 {
            buf_bits -= 8;
            let decoded = (buf >> buf_bits) as u8;
            buf &= (1u32 << buf_bits) - 1;

            if prefix_idx >= prefix.len() {
                break;
            }
            if decoded != prefix[prefix_idx] {
                return Ok(false);
            }
            prefix_idx += 1;
        }
    }

    Ok(prefix_idx >= prefix.len())
}

// ---------------------------------------------------------------------------
// PyPI upload token (macaroon V2)
// ---------------------------------------------------------------------------

/// Literal prefix of a PyPI upload token.
const PYPI_PREFIX: &[u8] = b"pypi-";

/// Expected first 12 bytes of the base64url-decoded macaroon V2 body.
///
/// ```text
/// Offset  Hex   Meaning
/// 0       0x02  Macaroon V2 version
/// 1       0x01  LOCATION field tag
/// 2       0x08  LOCATION length (8 = len("pypi.org"))
/// 3-10    ...   "pypi.org" (8 ASCII bytes)
/// 11      0x02  IDENTIFIER field tag
/// ```
const PYPI_HEADER: [u8; 12] = [
    0x02, 0x01, 0x08, b'p', b'y', b'p', b'i', b'.', b'o', b'r', b'g', 0x02,
];

/// Number of base64url characters needed to decode [`PYPI_HEADER`] (12 bytes).
///
/// `ceil(12 / 3) * 4 = 16`.
const PYPI_B64URL_HEADER_CHARS: usize = 16;

/// Minimum total token length: `pypi-` (5) + 16 base64url header chars = 21.
const PYPI_MIN_LEN: usize = PYPI_PREFIX.len() + PYPI_B64URL_HEADER_CHARS;

/// Validate a PyPI upload token (macaroon V2 binary header check).
///
/// Layout: `pypi-<base64url-encoded macaroon body>`.
///
/// The first 16 base64url characters decode to 12 bytes which must match
/// the known macaroon V2 header for `pypi.org`. Padding (`=`) is never
/// present — pymacaroons always strips it.
///
/// Returns `Indeterminate` for wrong prefix or insufficient length (the
/// regex match may have grabbed a wider span). Returns `Invalid` for
/// bad base64url characters or header mismatch.
fn validate_pypi_token(secret: &[u8]) -> OfflineVerdict {
    if secret.len() < PYPI_MIN_LEN {
        return OfflineVerdict::Indeterminate;
    }
    if !secret.starts_with(PYPI_PREFIX) {
        return OfflineVerdict::Indeterminate;
    }

    let body = &secret[PYPI_PREFIX.len()..];
    // Safety: PYPI_MIN_LEN == PYPI_PREFIX.len() + PYPI_B64URL_HEADER_CHARS,
    // so the length check above guarantees body.len() >= PYPI_B64URL_HEADER_CHARS.
    debug_assert!(body.len() >= PYPI_B64URL_HEADER_CHARS);

    // Decode 16 base64url chars → 12 bytes using deferred-invalidity loop.
    // Each group of 4 chars produces 3 bytes: 16 chars → 12 bytes exactly.
    let mut decoded = [0u8; 12];
    let mut invalid: u8 = 0;
    let mut buf: u32 = 0;
    let mut buf_bits: u32 = 0;
    let mut out_idx: usize = 0;

    for &b in &body[..PYPI_B64URL_HEADER_CHARS] {
        let v = BASE64URL_LUT[b as usize];
        invalid |= v;
        buf = (buf << 6) | (v & 0x3F) as u32;
        buf_bits += 6;

        if buf_bits >= 8 {
            buf_bits -= 8;
            decoded[out_idx] = (buf >> buf_bits) as u8;
            buf &= (1u32 << buf_bits) - 1;
            out_idx += 1;
        }
    }

    if invalid & 0x80 != 0 {
        return OfflineVerdict::Invalid;
    }

    if decoded == PYPI_HEADER {
        OfflineVerdict::Valid
    } else {
        OfflineVerdict::Invalid
    }
}

// ---------------------------------------------------------------------------
// Slack API tokens
// ---------------------------------------------------------------------------

/// Check that every byte in `seg` satisfies `pred`.
///
/// Uses OR-accumulation to minimize branches: the loop body avoids
/// early-exit, deferring the pass/fail decision until after all bytes are
/// checked. Whether individual predicate calls compile to branchless
/// instructions depends on the predicate and target (e.g., range checks
/// on AArch64 often compile to `cmp + cset`).
#[inline]
fn all_bytes(seg: &[u8], pred: fn(u8) -> bool) -> bool {
    let mut bad: u8 = 0;
    for &b in seg {
        bad |= !pred(b) as u8;
    }
    bad == 0
}

/// Check that a byte is ASCII alphanumeric or hyphen.
#[inline]
fn is_alnum_or_hyphen(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// Check that a byte is uppercase ASCII or digit.
#[inline]
fn is_upper_or_digit(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}

/// Check that a byte is lowercase ASCII or digit.
#[inline]
fn is_lower_or_digit(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// Check that a byte is a hex digit (case-insensitive).
#[inline]
fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

/// Split `data` on `sep` into at most `N` segments in a stack-local array.
///
/// Returns `(segments, count)` where `segments[..count]` are valid slices.
/// Behaves like `data.splitn(N, |&b| b == sep).collect::<Vec<_>>()` without
/// heap allocation.
fn splitn_stack<const N: usize>(data: &[u8], sep: u8) -> ([&[u8]; N], usize) {
    let mut segs: [&[u8]; N] = [&[]; N];
    let mut count = 0;
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == sep && count + 1 < N {
            segs[count] = &data[start..i];
            count += 1;
            start = i + 1;
        }
    }
    segs[count] = &data[start..];
    count += 1;
    (segs, count)
}

/// Validate a Slack API token by dispatching on prefix.
///
/// Compound prefixes (`xoxe.xoxb-`, `xoxe.xoxp-`) are checked first to
/// avoid misparse against simpler prefixes. Unknown prefixes return
/// `Indeterminate` for forward compatibility.
///
/// ## Dispatch table
///
/// | Prefix             | Sub-validator                         | Rules served                                          | Case        |
/// |--------------------|---------------------------------------|-------------------------------------------------------|-------------|
/// | `xoxe.xox[bp]-`   | [`validate_slack_config_access`]      | `slack-config-access-token`                           | insensitive |
/// | `xoxb-`            | [`validate_slack_xoxb`]               | `slack-bot-token`, `slack-legacy-bot-token`            | sensitive   |
/// | `xoxp-`            | [`validate_slack_user_token`]         | `slack-user-token`                                    | sensitive   |
/// | `xoxe-`            | [`validate_slack_xoxe`]               | `slack-config-refresh-token`, `slack-user-token`       | insensitive |
/// | `xapp-`            | [`validate_slack_xapp`]               | `slack-app-token`                                     | insensitive |
/// | `xox[os]-`         | [`validate_slack_legacy`]             | `slack-legacy-token`                                  | sensitive   |
/// | `xox[ar]-`         | [`validate_slack_legacy_workspace`]   | `slack-legacy-workspace-token`                        | sensitive   |
///
/// Compound prefixes are checked before simple ones so `xoxe.xoxb-` is not
/// misrouted through the `xoxe-` path. Unknown prefixes return `Indeterminate`
/// for forward compatibility with future Slack token formats.
fn validate_slack_token(secret: &[u8]) -> OfflineVerdict {
    // Need at least 5 bytes for the shortest prefix (xoxb-, xoxp-, etc.)
    if secret.len() < 5 {
        return OfflineVerdict::Indeterminate;
    }

    // Compound prefixes first (10 bytes: "xoxe.xoxb-" / "xoxe.xoxp-").
    if secret.len() >= 10 {
        let compound = &secret[..10];
        if compound[4] == b'.'
            && compound[..4].eq_ignore_ascii_case(b"xoxe")
            && (compound[5..9].eq_ignore_ascii_case(b"xoxb")
                || compound[5..9].eq_ignore_ascii_case(b"xoxp"))
            && compound[9] == b'-'
        {
            return validate_slack_config_access(&secret[10..]);
        }
    }

    // Simple prefixes (5 bytes: 4-char tag + '-').
    let prefix4 = &secret[..4];
    if secret[4] != b'-' {
        return OfflineVerdict::Indeterminate;
    }

    // At this point secret[4] == b'-', prefix is secret[..4].
    let p = prefix4;

    // Case-sensitive prefixes.
    if p == b"xoxb" {
        return validate_slack_xoxb(&secret[5..]);
    }
    if p == b"xoxp" {
        return validate_slack_user_token(&secret[5..]);
    }
    if p == b"xoxo" || p == b"xoxs" {
        return validate_slack_legacy(&secret[5..]);
    }
    if p == b"xoxa" || p == b"xoxr" {
        return validate_slack_legacy_workspace(&secret[5..]);
    }

    // Case-insensitive prefixes.
    if p.eq_ignore_ascii_case(b"xapp") {
        return validate_slack_xapp(&secret[5..]);
    }
    if p.eq_ignore_ascii_case(b"xoxe") {
        return validate_slack_xoxe(&secret[5..]);
    }

    OfflineVerdict::Indeterminate
}

/// Validate `xoxe.xox[bp]-` config access token.
///
/// Format after compound prefix: `{1 digit}-{163–166 upper+digit}`.
fn validate_slack_config_access(after_prefix: &[u8]) -> OfflineVerdict {
    let (segs, seg_count) = splitn_stack::<3>(after_prefix, b'-');
    if seg_count < 2 {
        return OfflineVerdict::Indeterminate;
    }

    let d = segs[0];
    if d.len() != 1 || !d[0].is_ascii_digit() {
        return OfflineVerdict::Invalid;
    }

    // Remaining body after first segment and hyphen.
    let body = &after_prefix[d.len() + 1..];
    if !(163..=166).contains(&body.len()) {
        return OfflineVerdict::Invalid;
    }
    if !all_bytes(body, is_upper_or_digit) {
        return OfflineVerdict::Invalid;
    }

    OfflineVerdict::Valid
}

/// Validate `xapp-` app-level token.
///
/// Format after prefix: `{1 digit}-{upper+digit}-{digits}-{lower+digit}`.
fn validate_slack_xapp(after_prefix: &[u8]) -> OfflineVerdict {
    let (segs, seg_count) = splitn_stack::<5>(after_prefix, b'-');
    if seg_count < 4 {
        return OfflineVerdict::Indeterminate;
    }

    // Segment 1: single digit.
    if segs[0].len() != 1 || !segs[0][0].is_ascii_digit() {
        return OfflineVerdict::Invalid;
    }
    // Segment 2: uppercase + digits, non-empty.
    if segs[1].is_empty() || !all_bytes(segs[1], is_upper_or_digit) {
        return OfflineVerdict::Invalid;
    }
    // Segment 3: digits, non-empty.
    if segs[2].is_empty() || !all_bytes(segs[2], |b| b.is_ascii_digit()) {
        return OfflineVerdict::Invalid;
    }
    // Segment 4: lowercase + digits, non-empty.
    if segs[3].is_empty() || !all_bytes(segs[3], is_lower_or_digit) {
        return OfflineVerdict::Invalid;
    }

    OfflineVerdict::Valid
}

/// Validate `xoxb-` bot token (current and legacy formats).
///
/// Current: `{d10-13}-{d10-13}-{alnum+hyphen tail}`.
/// Legacy:  `{d8-14}-{an18-26}`.
fn validate_slack_xoxb(after_prefix: &[u8]) -> OfflineVerdict {
    let (segs, seg_count) = splitn_stack::<4>(after_prefix, b'-');

    // Try current format: 3+ segments (d10-13, d10-13, tail with possible hyphens).
    if seg_count >= 3 {
        let s1 = segs[0];
        let s2 = segs[1];
        if (10..=13).contains(&s1.len())
            && all_bytes(s1, |b| b.is_ascii_digit())
            && (10..=13).contains(&s2.len())
            && all_bytes(s2, |b| b.is_ascii_digit())
        {
            // Tail: everything after second hyphen separator.
            let tail_start = s1.len() + 1 + s2.len() + 1;
            let tail = &after_prefix[tail_start..];
            if !tail.is_empty() && all_bytes(tail, is_alnum_or_hyphen) {
                return OfflineVerdict::Valid;
            }
        }
    }

    // Try legacy format: 2 segments (d8-14, an18-26).
    if seg_count >= 2 {
        let s1 = segs[0];
        if (8..=14).contains(&s1.len()) && all_bytes(s1, |b| b.is_ascii_digit()) {
            let tail_start = s1.len() + 1;
            let tail = &after_prefix[tail_start..];
            if (18..=26).contains(&tail.len()) && all_bytes(tail, |b| b.is_ascii_alphanumeric()) {
                return OfflineVerdict::Valid;
            }
        }
    }

    // Both current and legacy `xoxb-` formats were attempted and neither
    // matched. Return Indeterminate (not Invalid) so that unknown future
    // token layouts are not suppressed as false positives.
    OfflineVerdict::Indeterminate
}

/// Validate `xoxp-` / `xoxe-` user token.
///
/// Format after prefix: `{d10-13}-{d10-13}-{d10-13}-{an+hyphen 28-34}`.
///
/// Called directly for `xoxp-` tokens, and by [`validate_slack_xoxe`] when the
/// first segment has 10–13 digits (user/enterprise token vs config-refresh).
fn validate_slack_user_token(after_prefix: &[u8]) -> OfflineVerdict {
    let (segs, seg_count) = splitn_stack::<5>(after_prefix, b'-');
    if seg_count < 4 {
        return OfflineVerdict::Indeterminate;
    }

    // Three numeric segments (d10-13 each).
    for &seg in &segs[..3] {
        if !(10..=13).contains(&seg.len()) || !all_bytes(seg, |b| b.is_ascii_digit()) {
            return OfflineVerdict::Invalid;
        }
    }

    // Tail: everything after the third numeric segment and its hyphen.
    let tail_start = segs[0].len() + 1 + segs[1].len() + 1 + segs[2].len() + 1;
    let tail = &after_prefix[tail_start..];
    if !(28..=34).contains(&tail.len()) || !all_bytes(tail, is_alnum_or_hyphen) {
        return OfflineVerdict::Invalid;
    }

    OfflineVerdict::Valid
}

/// Validate `xoxe-` token (disambiguates config-refresh vs user token).
///
/// Config refresh: `{1 digit}-{146 upper+digit}`.
/// User/enterprise: same as [`validate_slack_user_token`] (3 numeric + tail).
fn validate_slack_xoxe(after_prefix: &[u8]) -> OfflineVerdict {
    // Disambiguate by first segment length:
    // - 1 digit → config refresh token
    // - 10-13 digits → user/enterprise token
    let first_seg_end = after_prefix.iter().position(|&b| b == b'-');
    let first_seg = match first_seg_end {
        Some(pos) => &after_prefix[..pos],
        None => return OfflineVerdict::Indeterminate,
    };

    if first_seg.len() == 1 && first_seg[0].is_ascii_digit() {
        // Config refresh: body after "digit-" is 146 upper+digit chars.
        let body = &after_prefix[first_seg.len() + 1..];
        if body.len() != 146 {
            return OfflineVerdict::Invalid;
        }
        if !all_bytes(body, is_upper_or_digit) {
            return OfflineVerdict::Invalid;
        }
        return OfflineVerdict::Valid;
    }

    if (10..=13).contains(&first_seg.len()) && all_bytes(first_seg, |b| b.is_ascii_digit()) {
        // User/enterprise token: delegate to user token validator.
        return validate_slack_user_token(after_prefix);
    }

    // First segment matches neither config-refresh (1 digit) nor user token
    // (10-13 digits). Return Indeterminate so unknown future formats are not
    // suppressed as false positives.
    OfflineVerdict::Indeterminate
}

/// Validate `xox[os]-` legacy token.
///
/// Format after prefix: `{d+}-{d+}-{d+}-{hex+}`.
fn validate_slack_legacy(after_prefix: &[u8]) -> OfflineVerdict {
    let (segs, seg_count) = splitn_stack::<5>(after_prefix, b'-');
    if seg_count < 4 {
        return OfflineVerdict::Indeterminate;
    }

    // Three digit-only segments.
    for &seg in &segs[..3] {
        if seg.is_empty() || !all_bytes(seg, |b| b.is_ascii_digit()) {
            return OfflineVerdict::Invalid;
        }
    }

    // Fourth segment: hex.
    let hex_start = segs[0].len() + 1 + segs[1].len() + 1 + segs[2].len() + 1;
    let hex_seg = &after_prefix[hex_start..];
    if hex_seg.is_empty() || !all_bytes(hex_seg, is_hex) {
        return OfflineVerdict::Invalid;
    }

    OfflineVerdict::Valid
}

/// Validate `xox[ar]-` legacy workspace token.
///
/// Format after prefix: `(?:{digit}-)?{an8-48}`.
fn validate_slack_legacy_workspace(after_prefix: &[u8]) -> OfflineVerdict {
    if after_prefix.is_empty() {
        return OfflineVerdict::Indeterminate;
    }

    // Check for optional leading "digit-" segment.
    let body =
        if after_prefix.len() >= 2 && after_prefix[0].is_ascii_digit() && after_prefix[1] == b'-' {
            &after_prefix[2..]
        } else {
            after_prefix
        };

    if !(8..=48).contains(&body.len()) {
        return OfflineVerdict::Invalid;
    }
    if !all_bytes(body, |b| b.is_ascii_alphanumeric()) {
        return OfflineVerdict::Invalid;
    }

    OfflineVerdict::Valid
}

// ---------------------------------------------------------------------------
// Bench-only exports
// ---------------------------------------------------------------------------

/// Bench hook for AWS access-key offline validation.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_offline_validate_aws_access_key(secret: &[u8]) -> bool {
    matches!(validate_aws_access_key(secret), OfflineVerdict::Valid)
}

/// Bench hook for Sentry org-token offline validation.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_offline_validate_sentry_org_token(secret: &[u8]) -> bool {
    matches!(validate_sentry_org_token(secret), OfflineVerdict::Valid)
}

/// Bench hook for PyPI upload-token offline validation.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_offline_validate_pypi_token(secret: &[u8]) -> bool {
    matches!(validate_pypi_token(secret), OfflineVerdict::Valid)
}

/// Bench hook for Slack token offline validation.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_offline_validate_slack_token(secret: &[u8]) -> bool {
    matches!(validate_slack_token(secret), OfflineVerdict::Valid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const BASE62_CHARS: &[u8; 62] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    fn base62_encode_u32(mut val: u32, buf: &mut [u8]) {
        for slot in buf.iter_mut().rev() {
            *slot = BASE62_CHARS[(val % 62) as usize];
            val /= 62;
        }
    }

    fn base64_decode(input: &[u8], output: &mut [u8]) -> Option<usize> {
        let max_decoded = input.len() * 3 / 4;
        if max_decoded > output.len() {
            return None;
        }
        let mut out_idx = 0;
        let mut buf: u32 = 0;
        let mut buf_bits: u32 = 0;
        for &b in input {
            let v = BASE64_LUT[b as usize];
            if v == 0xFE {
                continue;
            }
            if v == 0xFF {
                return None;
            }
            buf = (buf << 6) | v as u32;
            buf_bits += 6;
            if buf_bits >= 8 {
                buf_bits -= 8;
                if out_idx >= output.len() {
                    return None;
                }
                output[out_idx] = (buf >> buf_bits) as u8;
                buf &= (1u32 << buf_bits) - 1;
                out_idx += 1;
            }
        }
        Some(out_idx)
    }

    // ---- Base-62 round-trip ----

    #[test]
    fn base62_encode_decode_round_trip() {
        let values = [0u32, 1, 61, 62, 3843, 999_999, u32::MAX];
        for &val in &values {
            let mut buf = [0u8; 6];
            base62_encode_u32(val, &mut buf);
            let decoded = base62_decode_u32(&buf).unwrap();
            assert_eq!(val, decoded, "round-trip failed for {val}");
        }
    }

    #[test]
    fn base62_decode_invalid_char() {
        assert_eq!(base62_decode_u32(b"abc!ef"), None);
    }

    #[test]
    fn base62_decode_overflow() {
        // 7 chars of 'z' (max digit = 61) overflows u32.
        assert_eq!(base62_decode_u32(b"zzzzzzz"), None);
    }

    // ---- Hex decode ----

    #[test]
    fn hex_decode_valid() {
        assert_eq!(hex_decode_u32(b"00000000"), Some(0));
        assert_eq!(hex_decode_u32(b"ffffffff"), Some(u32::MAX));
        assert_eq!(hex_decode_u32(b"DEADBEEF"), Some(0xDEADBEEF));
        assert_eq!(hex_decode_u32(b"0000007b"), Some(123));
    }

    #[test]
    fn hex_decode_wrong_length() {
        assert_eq!(hex_decode_u32(b"0000000"), None);
        assert_eq!(hex_decode_u32(b"000000000"), None);
    }

    #[test]
    fn hex_decode_invalid_char() {
        assert_eq!(hex_decode_u32(b"0000000g"), None);
    }

    // ---- Base64 decode ----

    #[test]
    fn base64_decode_basic() {
        let mut buf = [0u8; 64];
        // "eyJpYXQiOg==" decodes to `{"iat":` (7 bytes).
        let input = b"eyJpYXQiOg==";
        let len = base64_decode(input, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"{\"iat\":");
    }

    #[test]
    fn base64_decode_no_padding() {
        let mut buf = [0u8; 64];
        // "QUJD" = "ABC"
        let len = base64_decode(b"QUJD", &mut buf).unwrap();
        assert_eq!(&buf[..len], b"ABC");
    }

    #[test]
    fn base64_decode_invalid_char() {
        let mut buf = [0u8; 64];
        assert_eq!(base64_decode(b"QUJ!", &mut buf), None);
    }

    // ---- CRC-32 + Base-62 validator ----

    #[test]
    fn crc32_base62_valid_token() {
        // Construct a token: [prefix(4)][payload(10)][checksum(6)]
        let prefix = b"pfx_";
        let payload = b"helloworld";
        let crc = crc32fast::hash(payload);
        let mut checksum = [0u8; 6];
        base62_encode_u32(crc, &mut checksum);

        let mut token = Vec::new();
        token.extend_from_slice(prefix);
        token.extend_from_slice(payload);
        token.extend_from_slice(&checksum);

        let spec = OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 4,
            payload_len: 10,
            checksum_len: 6,
        };
        assert_eq!(validate(spec, &token), OfflineVerdict::Valid);
    }

    #[test]
    fn crc32_base62_invalid_checksum() {
        let prefix = b"pfx_";
        let payload = b"helloworld";
        let mut checksum = [0u8; 6];
        base62_encode_u32(12345, &mut checksum); // wrong CRC

        let mut token = Vec::new();
        token.extend_from_slice(prefix);
        token.extend_from_slice(payload);
        token.extend_from_slice(&checksum);

        let spec = OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 4,
            payload_len: 10,
            checksum_len: 6,
        };
        assert_eq!(validate(spec, &token), OfflineVerdict::Invalid);
    }

    #[test]
    fn crc32_base62_too_short() {
        let spec = OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 4,
            payload_len: 10,
            checksum_len: 6,
        };
        assert_eq!(validate(spec, b"short"), OfflineVerdict::Indeterminate);
    }

    // ---- GitHub fine-grained PAT ----

    #[test]
    fn github_pat_valid() {
        // Build a valid token: github_pat_ + 76 chars + 6 char CRC.
        let mut token = Vec::new();
        token.extend_from_slice(b"github_pat_");
        // 76 payload chars (type + underscore + random).
        let payload_filler: Vec<u8> = std::iter::repeat_n(b'A', 76).collect();
        token.extend_from_slice(&payload_filler);

        // CRC of everything so far (87 bytes).
        let crc = crc32fast::hash(&token);
        let mut checksum = [0u8; 6];
        base62_encode_u32(crc, &mut checksum);
        token.extend_from_slice(&checksum);

        assert_eq!(token.len(), 93);
        assert_eq!(
            validate(OfflineValidationSpec::GithubFinegrainedPat, &token),
            OfflineVerdict::Valid,
        );
    }

    #[test]
    fn github_pat_invalid_checksum() {
        let mut token = Vec::new();
        token.extend_from_slice(b"github_pat_");
        let payload_filler: Vec<u8> = std::iter::repeat_n(b'A', 76).collect();
        token.extend_from_slice(&payload_filler);
        token.extend_from_slice(b"000000"); // wrong checksum

        assert_eq!(
            validate(OfflineValidationSpec::GithubFinegrainedPat, &token),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn github_pat_too_short() {
        assert_eq!(
            validate(
                OfflineValidationSpec::GithubFinegrainedPat,
                b"github_pat_short"
            ),
            OfflineVerdict::Indeterminate,
        );
    }

    #[test]
    fn github_pat_wrong_prefix() {
        let token = vec![b'X'; 93];
        assert_eq!(
            validate(OfflineValidationSpec::GithubFinegrainedPat, &token),
            OfflineVerdict::Indeterminate,
        );
    }

    // ---- Grafana service-account token ----

    #[test]
    fn grafana_valid() {
        let mut token = Vec::new();
        token.extend_from_slice(b"glsa_");
        let random: Vec<u8> = std::iter::repeat_n(b'a', 32).collect();
        token.extend_from_slice(&random);

        // CRC over `glsa_<32 chars>` (37 bytes).
        let crc = crc32fast::hash(&token);
        token.push(b'_');
        let hex = format!("{crc:08x}");
        token.extend_from_slice(hex.as_bytes());

        assert_eq!(token.len(), 46);
        assert_eq!(
            validate(OfflineValidationSpec::GrafanaServiceAccount, &token),
            OfflineVerdict::Valid,
        );
    }

    #[test]
    fn grafana_invalid_checksum() {
        let mut token = Vec::new();
        token.extend_from_slice(b"glsa_");
        token.extend_from_slice(&[b'a'; 32]);
        token.push(b'_');
        token.extend_from_slice(b"deadbeef"); // wrong CRC

        assert_eq!(
            validate(OfflineValidationSpec::GrafanaServiceAccount, &token),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn grafana_too_short() {
        assert_eq!(
            validate(OfflineValidationSpec::GrafanaServiceAccount, b"glsa_short"),
            OfflineVerdict::Indeterminate,
        );
    }

    // ---- AWS access key ----

    #[test]
    fn aws_valid_charset() {
        // AKIA followed by 16 chars from [A-Z2-7].
        let key = b"AKIAIOSFODNN7EXAMPLE";
        assert_eq!(key.len(), 20);
        let verdict = validate(OfflineValidationSpec::AwsAccessKey, key);
        // Valid structure — account ID check may yield Valid or Indeterminate.
        assert_ne!(verdict, OfflineVerdict::Invalid);
    }

    #[test]
    fn aws_invalid_charset() {
        // lowercase letters are not in [A-Z2-7].
        let key = b"AKIAiosfodnn7example";
        assert_eq!(
            validate(OfflineValidationSpec::AwsAccessKey, key),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn aws_too_short() {
        assert_eq!(
            validate(OfflineValidationSpec::AwsAccessKey, b"AKIA1234"),
            OfflineVerdict::Indeterminate,
        );
    }

    #[test]
    fn aws_unknown_prefix() {
        let key = b"XXXX1234567890123456";
        assert_eq!(
            validate(OfflineValidationSpec::AwsAccessKey, key),
            OfflineVerdict::Indeterminate,
        );
    }

    #[test]
    fn aws_a3t_prefix_valid() {
        // A3T followed by uppercase letter, then 16 chars from [A-Z2-7].
        let key = b"A3TXABCDEFGHIJKLMNOP";
        assert_eq!(key.len(), 20);
        let verdict = validate(OfflineValidationSpec::AwsAccessKey, key);
        assert_ne!(verdict, OfflineVerdict::Invalid);
    }

    // ---- Sentry org token ----

    #[test]
    fn sentry_valid_structure() {
        // Build: sntrys_<base64 of {"iat":...}>_<43 base64 chars>
        let payload_json = b"{\"iat\":1234567890,\"region_url\":\"https://sentry.io\"}";
        // Base64-encode the payload.
        let mut b64_payload = Vec::new();
        base64_encode_for_test(payload_json, &mut b64_payload);

        let mut token = Vec::new();
        token.extend_from_slice(b"sntrys_");
        token.extend_from_slice(&b64_payload);
        token.push(b'_');
        // 43-char base64 signature.
        let sig: Vec<u8> = std::iter::repeat_n(b'A', 43).collect();
        token.extend_from_slice(&sig);

        assert_eq!(
            validate(OfflineValidationSpec::SentryOrgToken, &token),
            OfflineVerdict::Valid,
        );
    }

    #[test]
    fn sentry_invalid_payload() {
        // Payload decodes to something not starting with {"iat":
        let payload = b"not_json_at_all_here";
        let mut b64_payload = Vec::new();
        base64_encode_for_test(payload, &mut b64_payload);

        let mut token = Vec::new();
        token.extend_from_slice(b"sntrys_");
        token.extend_from_slice(&b64_payload);
        token.push(b'_');
        let sig: Vec<u8> = std::iter::repeat_n(b'A', 43).collect();
        token.extend_from_slice(&sig);

        assert_eq!(
            validate(OfflineValidationSpec::SentryOrgToken, &token),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn sentry_literal_cases() {
        use OfflineVerdict::{Indeterminate, Invalid};

        let invalid_payload_char = {
            let mut t = b"sntrys_eyJpYXQiO@==_".to_vec();
            t.extend_from_slice(&[b'A'; 43]);
            t
        };

        let cases: Vec<(&str, Vec<u8>, OfflineVerdict)> = vec![
            ("invalid_payload_char", invalid_payload_char, Invalid),
            ("too_short", b"sntrys_".to_vec(), Indeterminate),
            ("wrong_prefix", b"sntryu_abc".to_vec(), Indeterminate),
            (
                "no_separator",
                b"sntrys_eyJpYXQiOjEyMzR9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
                Indeterminate,
            ),
        ];

        for (label, token, expected) in &cases {
            assert_eq!(
                validate(OfflineValidationSpec::SentryOrgToken, token),
                *expected,
                "case: {label}",
            );
        }
    }

    // ---- Dispatcher ----

    #[test]
    fn dispatch_crc32_base62() {
        let spec = OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 0,
            payload_len: 3,
            checksum_len: 6,
        };
        let payload = b"abc";
        let crc = crc32fast::hash(payload);
        let mut checksum = [0u8; 6];
        base62_encode_u32(crc, &mut checksum);

        let mut token = Vec::new();
        token.extend_from_slice(payload);
        token.extend_from_slice(&checksum);

        assert_eq!(validate(spec, &token), OfflineVerdict::Valid);
    }

    // ---- Step 6: edge-case tests for branchless optimizations ----

    #[test]
    fn sentry_invalid_sig_char() {
        // Invalid `@` at position 21 in the 43-char signature.
        let payload_json = b"{\"iat\":1234567890}";
        let mut b64_payload = Vec::new();
        base64_encode_for_test(payload_json, &mut b64_payload);

        let mut token = Vec::new();
        token.extend_from_slice(b"sntrys_");
        token.extend_from_slice(&b64_payload);
        token.push(b'_');
        // 43-char sig with an invalid char at position 21.
        let mut sig = vec![b'A'; 43];
        sig[21] = b'@';
        token.extend_from_slice(&sig);

        assert_eq!(
            validate(OfflineValidationSpec::SentryOrgToken, &token),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn sentry_sig_with_padding_char() {
        // Padding `=` in signature must reject (not valid base64 data char).
        let payload_json = b"{\"iat\":1234567890}";
        let mut b64_payload = Vec::new();
        base64_encode_for_test(payload_json, &mut b64_payload);

        let mut token = Vec::new();
        token.extend_from_slice(b"sntrys_");
        token.extend_from_slice(&b64_payload);
        token.push(b'_');
        let mut sig = vec![b'A'; 43];
        sig[42] = b'=';
        token.extend_from_slice(&sig);

        assert_eq!(
            validate(OfflineValidationSpec::SentryOrgToken, &token),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn base62_decode_just_over_u32_max() {
        // 7 base-62 chars that overflow u32 (62^6 = 56_800_235_584 > u32::MAX).
        // "1000000" in base-62 = 62^6 = 56_800_235_584.
        assert_eq!(base62_decode_u32(b"1000000"), None);
    }

    // ---- PyPI upload token ----

    /// Build a PyPI token with the correct base64url-encoded header.
    fn build_pypi_token(body_suffix: &[u8]) -> Vec<u8> {
        // base64url of PYPI_HEADER is "AgEIcHlwaS5vcmcC" (16 chars).
        let mut token = Vec::new();
        token.extend_from_slice(b"pypi-AgEIcHlwaS5vcmcC");
        token.extend_from_slice(body_suffix);
        token
    }

    #[test]
    fn pypi_valid_token() {
        // 16 header chars + 50 body chars → well above minimum.
        let filler: Vec<u8> = std::iter::repeat_n(b'A', 50).collect();
        let token = build_pypi_token(&filler);
        assert_eq!(
            validate(OfflineValidationSpec::PyPiToken, &token),
            OfflineVerdict::Valid,
        );
    }

    #[test]
    fn pypi_invalid_body_char() {
        // '@' is not a valid base64url character.
        let mut token = build_pypi_token(&[b'A'; 50]);
        token[5] = b'@'; // corrupt 1st base64url char of body
        assert_eq!(
            validate(OfflineValidationSpec::PyPiToken, &token),
            OfflineVerdict::Invalid,
        );
    }

    #[test]
    fn pypi_literal_cases() {
        use OfflineVerdict::{Indeterminate, Invalid};

        let wrong_header = {
            let mut t = b"pypi-AAAAAAAAAAAAAAAA".to_vec();
            t.extend_from_slice(&[b'B'; 50]);
            t
        };

        let cases: Vec<(&str, Vec<u8>, OfflineVerdict)> = vec![
            ("wrong_header", wrong_header, Invalid),
            ("too_short", b"pypi-AgEI".to_vec(), Indeterminate),
            (
                "wrong_prefix",
                b"not-pypi-AgEIcHlwaS5vcmcCxxxxxxxxxxxxxxxxxxxxxxxx".to_vec(),
                Indeterminate,
            ),
            ("empty_body", b"pypi-".to_vec(), Indeterminate),
        ];

        for (label, token, expected) in &cases {
            assert_eq!(
                validate(OfflineValidationSpec::PyPiToken, token),
                *expected,
                "case: {label}",
            );
        }
    }

    // ---- Slack tokens (table-driven) ----

    #[test]
    fn slack_token_cases() {
        use OfflineVerdict::{Indeterminate, Valid};

        // Dynamic tokens that require Vec construction.
        let config_access = {
            let mut t = b"xoxe.xoxb-1-".to_vec();
            t.extend_from_slice(&[b'A'; 165]);
            t
        };
        let config_refresh = {
            let mut t = b"xoxe-1-".to_vec();
            t.extend_from_slice(&[b'A'; 146]);
            t
        };
        let config_access_xoxp = {
            let mut t = b"xoxe.xoxp-1-".to_vec();
            t.extend_from_slice(&[b'Z'; 163]);
            t
        };

        let cases: Vec<(&str, Vec<u8>, OfflineVerdict)> = vec![
            (
                "bot_current",
                b"xoxb-1234567890-1234567890-abcDEF12345678901234abcd".to_vec(),
                Valid,
            ),
            (
                "bot_legacy",
                b"xoxb-12345678-aBcDeFgHiJkLmNoPqRsT".to_vec(),
                Valid,
            ),
            (
                "bot_invalid_segments",
                b"xoxb-123-abc".to_vec(),
                Indeterminate,
            ),
            (
                "user",
                b"xoxp-1234567890-1234567890-1234567890-abcdefghijABCDEFGHIJ1234567890".to_vec(),
                Valid,
            ),
            (
                "xapp",
                b"xapp-1-ABCD1234567-5678901234-abcdef1234567890".to_vec(),
                Valid,
            ),
            ("config_access", config_access, Valid),
            ("config_refresh", config_refresh, Valid),
            ("legacy", b"xoxo-123-456-789-deadbeef".to_vec(), Valid),
            (
                "legacy_workspace",
                b"xoxa-2-abcdefgh12345678".to_vec(),
                Valid,
            ),
            ("unknown_prefix", b"xoxz-something".to_vec(), Indeterminate),
            ("too_short", b"xox".to_vec(), Indeterminate),
            (
                "case_insensitive_xapp",
                b"XAPP-1-ABCDEF123-456789-abcdef12".to_vec(),
                Valid,
            ),
            (
                "xoxe_user_format",
                b"xoxe-1234567890-1234567890-1234567890-abcdefghijABCDEFGHIJ1234567890".to_vec(),
                Valid,
            ),
            ("config_access_xoxp", config_access_xoxp, Valid),
            ("xoxr_workspace", b"xoxr-abcdefghij12345678".to_vec(), Valid),
            (
                "xoxs_legacy",
                b"xoxs-123-456-789-0123456789abcdef".to_vec(),
                Valid,
            ),
        ];

        for (label, token, expected) in &cases {
            assert_eq!(
                validate(OfflineValidationSpec::SlackToken, token),
                *expected,
                "case: {label}",
            );
        }
    }

    // ---- Test-only helper ----

    /// Minimal base64 encoder for constructing test vectors.
    fn base64_encode_for_test(input: &[u8], output: &mut Vec<u8>) {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut i = 0;
        while i + 2 < input.len() {
            let n =
                ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
            output.push(ALPHABET[((n >> 18) & 63) as usize]);
            output.push(ALPHABET[((n >> 12) & 63) as usize]);
            output.push(ALPHABET[((n >> 6) & 63) as usize]);
            output.push(ALPHABET[(n & 63) as usize]);
            i += 3;
        }

        let remaining = input.len() - i;
        if remaining == 2 {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            output.push(ALPHABET[((n >> 18) & 63) as usize]);
            output.push(ALPHABET[((n >> 12) & 63) as usize]);
            output.push(ALPHABET[((n >> 6) & 63) as usize]);
            output.push(b'=');
        } else if remaining == 1 {
            let n = (input[i] as u32) << 16;
            output.push(ALPHABET[((n >> 18) & 63) as usize]);
            output.push(ALPHABET[((n >> 12) & 63) as usize]);
            output.push(b'=');
            output.push(b'=');
        }
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptest_offline {
    use super::*;
    use proptest::prelude::*;

    const PROPTEST_CASES: u32 = 256;

    const BASE62_CHARS: &[u8; 62] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    fn base62_encode_u32(mut val: u32, buf: &mut [u8]) {
        for slot in buf.iter_mut().rev() {
            *slot = BASE62_CHARS[(val % 62) as usize];
            val /= 62;
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        #[test]
        fn crc32_base62_roundtrip_valid(payload in prop::collection::vec(any::<u8>(), 10..=10)) {
            let crc = crc32fast::hash(&payload);
            let mut checksum = [0u8; 6];
            base62_encode_u32(crc, &mut checksum);

            let mut token = b"pfx_".to_vec();
            token.extend_from_slice(&payload);
            token.extend_from_slice(&checksum);

            let spec = OfflineValidationSpec::Crc32Base62 {
                prefix_skip: 4,
                payload_len: 10,
                checksum_len: 6,
            };
            prop_assert_eq!(validate(spec, &token), OfflineVerdict::Valid);
        }

        #[test]
        fn github_pat_roundtrip_valid(
            body in prop::collection::vec(b'A'..=b'z', 76..=76)
        ) {
            let mut token = b"github_pat_".to_vec();
            token.extend_from_slice(&body);
            let crc = crc32fast::hash(&token);
            let mut checksum = [0u8; 6];
            base62_encode_u32(crc, &mut checksum);
            token.extend_from_slice(&checksum);

            prop_assert_eq!(token.len(), 93);
            prop_assert_eq!(
                validate(OfflineValidationSpec::GithubFinegrainedPat, &token),
                OfflineVerdict::Valid,
            );
        }

        #[test]
        fn grafana_roundtrip_valid(random in "[a-zA-Z0-9]{32}") {
            let mut token = b"glsa_".to_vec();
            token.extend_from_slice(random.as_bytes());
            let crc = crc32fast::hash(&token);
            token.push(b'_');
            let hex = format!("{crc:08x}");
            token.extend_from_slice(hex.as_bytes());

            prop_assert_eq!(token.len(), 46);
            prop_assert_eq!(
                validate(OfflineValidationSpec::GrafanaServiceAccount, &token),
                OfflineVerdict::Valid,
            );
        }

        #[test]
        fn base62_roundtrip(val in any::<u32>()) {
            let mut buf = [0u8; 6];
            base62_encode_u32(val, &mut buf);
            prop_assert_eq!(base62_decode_u32(&buf), Some(val));
        }
    }
}
