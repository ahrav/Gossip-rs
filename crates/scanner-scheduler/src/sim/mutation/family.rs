//! Token family definitions and deterministic valid-token generators.
//!
//! A "token family" is an archetype of a real-world secret format (AWS access
//! key, GitHub PAT, JWT, etc.). Each family encapsulates three pieces of
//! knowledge needed to build mutation-based counterexample tests:
//!
//! 1. **Generation** ([`TokenFamily::gen_valid`]) -- produce a structurally
//!    valid token from a deterministic seed. The generated token must pass the
//!    corresponding `engine/offline_validate.rs` validator (prefix, charset,
//!    length, checksum) so that it registers as a true positive in the absence
//!    of mutations.
//!
//! 2. **Allowed operators** ([`TokenFamily::allowed_ops`]) -- declare which
//!    mutation operator kinds are meaningful for this format. For example,
//!    `ChecksumCorrupt` only applies to families that carry a CRC.
//!
//! 3. **Expectation oracle** ([`TokenFamily::expectation`]) -- given a
//!    canonical token and a sequence of mutations, predict whether the
//!    detection engine must match, must not match, or may match. This is the
//!    ground-truth oracle that test harnesses assert against.
//!
//! Format details (prefix, body length, checksum algorithm and scope) are kept
//! in sync with `engine/offline_validate.rs` and `default_rules.yaml`.

use serde::{Deserialize, Serialize};

use super::encode::{
    base62_encode_u32, base64_encode_std, base64url_encode_nopad, percent_encode_all, BASE62_CHARS,
};
use super::op::{MutOp, MutOpKind};
use crate::sim::rng::SimRng;

/// Expected detection outcome for a mutated token.
///
/// This three-valued logic lets the test oracle distinguish between mutations
/// that **provably** break a detection invariant and mutations whose effect
/// depends on engine heuristics (entropy thresholds, boundary lookahead, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// The engine **must** detect this token. No mutation alters a property
    /// the engine checks, so a miss is a false negative bug.
    MustMatch,
    /// The engine **must not** detect this token. At least one mutation breaks
    /// a hard constraint (length, charset, prefix, or checksum), so a hit is
    /// a false positive bug.
    ///
    /// Note: the mutation adapter tolerates matches for tokens predicted as
    /// MustNotMatch due to context-wrapper boundary effects; see
    /// [`adapter::check_mutation_expectations`] for rationale.
    MustNotMatch,
    /// The engine **may or may not** detect this token. The mutation affects
    /// a soft heuristic (entropy, encoding depth, trailing bytes), so either
    /// outcome is acceptable.
    MayMatch,
}

/// AWS base-32 alphabet (RFC 4648 section 6): `A`--`Z` map to 0--25, `2`--`7`
/// map to 26--31. Used for the 16-character body of AWS access key IDs.
const AWS_BASE32_CHARS: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Token family describing a specific secret format.
///
/// Each variant models one class of real-world credential. The set is not
/// exhaustive -- it covers the format archetypes that exercise distinct code
/// paths in the detection engine: fixed-prefix with base-32 body, CRC-bearing
/// tokens (two different checksum scopes), structured multi-segment tokens
/// (JWT), and opaque encoded blobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenFamily {
    /// AWS access key ID: literal `AKIA` prefix + 16 base-32 characters = 20
    /// bytes total. No checksum; validation relies on prefix + charset + length.
    AwsAccessKey,
    /// GitHub fine-grained PAT: `github_pat_` (11 bytes) + 76 base-62 body +
    /// 6 base-62 CRC-32 characters = 93 bytes. The CRC is computed over the
    /// first 87 bytes (prefix **included**).
    GithubFinegrainedPat,
    /// GitHub classic PAT: `ghp_` (4 bytes) + 30 base-62 body + 6 base-62
    /// CRC-32 characters = 40 bytes. The CRC is computed over the payload only
    /// (bytes 4--33, prefix **excluded**).
    GithubClassicPat,
    /// JWT-like token: three dot-separated base64url segments
    /// (`header.payload.signature`). Header and payload start with `eyJ`
    /// (the base64url prefix for any JSON object starting with `{"`).
    JwtLike,
    /// Opaque base64-encoded blob: `base64(24--48 random bytes)`. Variable
    /// length; no structural prefix or checksum.
    Base64Blob,
    /// Opaque percent-encoded blob: every byte encoded as `%XX` from 16--32
    /// random source bytes. Variable length; no structural prefix or checksum.
    UrlEncodedBlob,
}

/// Compile-time assertion: `rule_id()` assumes `ALL` has exactly 6 entries.
const _: () = assert!(TokenFamily::ALL.len() == 6);

impl TokenFamily {
    /// All token families, for exhaustive iteration in tests.
    pub const ALL: [TokenFamily; 6] = [
        TokenFamily::AwsAccessKey,
        TokenFamily::GithubFinegrainedPat,
        TokenFamily::GithubClassicPat,
        TokenFamily::JwtLike,
        TokenFamily::Base64Blob,
        TokenFamily::UrlEncodedBlob,
    ];

    /// Positional index of this family in [`TokenFamily::ALL`], used as the
    /// rule ID throughout the mutation adapter.
    ///
    /// This is the single source of truth for family→rule_id mapping. Both
    /// scenario construction and post-run checking use it, so rule IDs are
    /// consistent across the entire mutation pipeline.
    pub const fn rule_id(self) -> u32 {
        match self {
            TokenFamily::AwsAccessKey => 0,
            TokenFamily::GithubFinegrainedPat => 1,
            TokenFamily::GithubClassicPat => 2,
            TokenFamily::JwtLike => 3,
            TokenFamily::Base64Blob => 4,
            TokenFamily::UrlEncodedBlob => 5,
        }
    }

    /// Generate a structurally valid token for this family.
    ///
    /// The returned token satisfies all format constraints (prefix, charset,
    /// length, checksum) and is therefore expected to be detected by the engine
    /// in the absence of any mutations. Output is fully deterministic: the same
    /// `rng` state always produces the same byte sequence.
    pub fn gen_valid(&self, rng: &mut SimRng) -> Vec<u8> {
        match self {
            TokenFamily::AwsAccessKey => gen_aws_access_key(rng),
            TokenFamily::GithubFinegrainedPat => gen_github_fine_grained_pat(rng),
            TokenFamily::GithubClassicPat => gen_github_classic_pat(rng),
            TokenFamily::JwtLike => gen_jwt_like(rng),
            TokenFamily::Base64Blob => gen_base64_blob(rng),
            TokenFamily::UrlEncodedBlob => gen_url_encoded_blob(rng),
        }
    }

    /// Conservative upper bound on numeric mutation parameters (e.g.
    /// `Truncate { len }`, `EntropyReduce { count }`) for this family.
    ///
    /// Approximates or slightly exceeds the canonical token length so that
    /// randomly generated values stay within realistic ranges rather than
    /// producing degenerate cases like `Truncate { len: usize::MAX }`.
    pub fn param_bound(self) -> usize {
        match self {
            TokenFamily::AwsAccessKey => 20,
            TokenFamily::GithubFinegrainedPat => 93,
            TokenFamily::GithubClassicPat => 40,
            TokenFamily::JwtLike => 200,
            TokenFamily::Base64Blob => 68,
            TokenFamily::UrlEncodedBlob => 96,
        }
    }

    /// Mutation operator kinds that produce meaningful test cases for this family.
    ///
    /// Only CRC-bearing families include `ChecksumCorrupt` (the XOR of the
    /// last byte may or may not affect detection for other families). Blob
    /// families exclude `PrefixMangle` because they have no structural prefix
    /// to corrupt.
    pub fn allowed_ops(&self) -> &'static [MutOpKind] {
        use MutOpKind::*;
        match self {
            TokenFamily::AwsAccessKey => &[
                Truncate,
                CharsetViolate,
                PrefixMangle,
                EntropyReduce,
                Encode,
                Extend,
            ],
            TokenFamily::GithubFinegrainedPat | TokenFamily::GithubClassicPat => &[
                Truncate,
                CharsetViolate,
                PrefixMangle,
                ChecksumCorrupt,
                EntropyReduce,
                Encode,
                Extend,
            ],
            TokenFamily::JwtLike => &[
                Truncate,
                CharsetViolate,
                PrefixMangle,
                EntropyReduce,
                Encode,
                Extend,
            ],
            TokenFamily::Base64Blob | TokenFamily::UrlEncodedBlob => {
                &[Truncate, CharsetViolate, EntropyReduce, Encode, Extend]
            }
        }
    }

    /// Predict the detection outcome after applying the given mutations.
    ///
    /// Returns a three-valued [`Outcome`]:
    /// - `MustMatch` -- no mutation alters a property the engine checks, so
    ///   the engine **must** still detect this token.
    /// - `MustNotMatch` -- at least one mutation provably breaks a hard
    ///   constraint (length, charset, prefix, or checksum), so the engine
    ///   **must not** detect this token.
    /// - `MayMatch` -- the mutation may or may not defeat detection depending
    ///   on engine heuristics (e.g. entropy thresholds), so the test harness
    ///   should accept either outcome.
    ///
    /// The oracle evaluates the full operator chain left-to-right, tracking
    /// the running token length so that later operators (e.g. a `Truncate`
    /// after an `Extend`) can be evaluated against the post-mutation state
    /// rather than the original canonical token. A `MustNotMatch` from any
    /// operator immediately dominates the result. Soft effects (`MayMatch`)
    /// are accumulated but can be overridden by a later hard breaker.
    ///
    /// Receives the canonical (pre-mutation) token so that length-dependent
    /// operators like `Truncate` can compare against the original size.
    pub fn expectation(&self, canonical: &[u8], ops: &[MutOp]) -> Outcome {
        if ops.is_empty() {
            return Outcome::MustMatch;
        }

        let canonical_len = canonical.len();
        let mut running_len = canonical_len;
        let mut worst = Outcome::MustMatch;

        for op in ops {
            match op {
                MutOp::Truncate { len } => {
                    if *len < running_len {
                        running_len = *len;
                    }
                    // A truncated length below the canonical length is a hard break.
                    if running_len < canonical_len {
                        return Outcome::MustNotMatch;
                    }
                }
                MutOp::CharsetViolate { positions, .. } => {
                    if positions.iter().any(|&p| p < running_len) {
                        return Outcome::MustNotMatch;
                    }
                }
                MutOp::PrefixMangle { replacement } if !replacement.is_empty() => {
                    return Outcome::MustNotMatch;
                }
                MutOp::ChecksumCorrupt => {
                    return match self {
                        TokenFamily::GithubFinegrainedPat | TokenFamily::GithubClassicPat => {
                            Outcome::MustNotMatch
                        }
                        _ => Outcome::MayMatch,
                    };
                }
                MutOp::EntropyReduce { count, .. } if *count > 0 => {
                    worst = Outcome::MayMatch;
                }
                MutOp::Encode { repr } => {
                    use super::encode::SecretRepr;
                    match repr {
                        // Identity encodings do not alter the bytes.
                        SecretRepr::Raw | SecretRepr::Nested { depth: 0 } => {}
                        _ => return Outcome::MayMatch,
                    }
                }
                MutOp::Extend { suffix } if !suffix.is_empty() => {
                    running_len += suffix.len();
                    worst = Outcome::MayMatch;
                }
                _ => {}
            }
        }

        worst
    }
}

// ---------------------------------------------------------------------------
// Per-family generators
// ---------------------------------------------------------------------------

/// Maximum valid AWS account ID. The engine's validator
/// (`engine/offline_validate.rs`) rejects decoded IDs above this threshold.
const AWS_MAX_ACCOUNT_ID: u64 = 999_999_999_999;

/// Generate an AWS access key ID: `AKIA` prefix + 16 base-32 characters.
///
/// The `AKIA` prefix identifies a long-term credential (as opposed to `ASIA`
/// for temporary STS tokens). The 16-character body encodes 80 bits in RFC 4648
/// base-32 with an embedded 40-bit account ID at bits \[1..41\]. The engine
/// validator rejects account IDs above 999,999,999,999, so we construct the
/// 80-bit payload explicitly rather than picking random base-32 chars:
///
/// ```text
/// Bit layout (MSB first across 10 decoded bytes):
///   [0]     flag bit (random)
///   [1..41] account ID (uniform in 0..=999_999_999_999)
///   [41..80] remaining 39 bits (random)
/// ```
fn gen_aws_access_key(rng: &mut SimRng) -> Vec<u8> {
    let flag: u8 = rng.gen_range(0, 2) as u8;
    let account_id: u64 = rng.gen_range(0, (AWS_MAX_ACCOUNT_ID + 1) as u32) as u64
        | ((rng.gen_range(0, (((AWS_MAX_ACCOUNT_ID + 1) >> 32) + 1) as u32) as u64) << 32);
    // Clamp in case the two-part generation overshot.
    let account_id = account_id % (AWS_MAX_ACCOUNT_ID + 1);

    let remaining_hi: u32 = rng.gen_range(0, 1 << 7); // 7 bits
    let remaining_lo: u32 = rng.gen_range(0, u32::MAX); // 32 bits

    // Pack into 10 bytes (80 bits, MSB first).
    // Byte 0: [flag(1)][account_id bits 39..33(7)]
    // Bytes 1-4: account_id bits 32..0
    // Byte 5: [account_id bit 0 (already in byte 4)] — actually:
    //   byte 5 top bit = account_id bit 0, lower 7 bits = remaining[0..7]
    // Bytes 6-9: remaining[7..39]
    let mut decoded = [0u8; 10];
    decoded[0] = (flag << 7) | ((account_id >> 33) as u8 & 0x7F);
    decoded[1] = (account_id >> 25) as u8;
    decoded[2] = (account_id >> 17) as u8;
    decoded[3] = (account_id >> 9) as u8;
    decoded[4] = (account_id >> 1) as u8;
    decoded[5] = ((account_id as u8 & 1) << 7) | (remaining_hi as u8 & 0x7F);
    decoded[6] = (remaining_lo >> 24) as u8;
    decoded[7] = (remaining_lo >> 16) as u8;
    decoded[8] = (remaining_lo >> 8) as u8;
    decoded[9] = remaining_lo as u8;

    // Encode 10 bytes as 16 base-32 characters (5 bits per char).
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(b"AKIA");

    let mut bit_buf: u64 = 0;
    let mut bits_in_buf: u32 = 0;
    for &byte in &decoded {
        bit_buf = (bit_buf << 8) | byte as u64;
        bits_in_buf += 8;
        while bits_in_buf >= 5 {
            bits_in_buf -= 5;
            let idx = ((bit_buf >> bits_in_buf) & 0x1F) as usize;
            out.push(AWS_BASE32_CHARS[idx]);
        }
    }
    debug_assert_eq!(out.len(), 20);
    out
}

/// Generate a GitHub fine-grained PAT.
///
/// Layout: `github_pat_` (11 bytes) + 76 random base-62 body + 6 base-62 CRC
/// = 93 bytes total. The CRC-32 is computed over the **entire** first 87 bytes
/// (prefix + body), which differs from the classic PAT format where the prefix
/// is excluded from the checksum scope.
fn gen_github_fine_grained_pat(rng: &mut SimRng) -> Vec<u8> {
    let mut out = Vec::with_capacity(93);
    out.extend_from_slice(b"github_pat_");
    // 76 random base-62 body chars
    for _ in 0..76 {
        let idx = rng.gen_range(0, 62) as usize;
        out.push(BASE62_CHARS[idx]);
    }
    debug_assert_eq!(out.len(), 87);
    // CRC-32 of first 87 bytes (prefix included)
    let crc = crc32fast::hash(&out[..87]);
    let mut cksum = [0u8; 6];
    base62_encode_u32(crc, &mut cksum);
    out.extend_from_slice(&cksum);
    debug_assert_eq!(out.len(), 93);
    out
}

/// Generate a GitHub classic PAT.
///
/// Layout: `ghp_` (4 bytes) + 30 random base-62 body + 6 base-62 CRC = 40
/// bytes total. The CRC-32 is computed over the **payload only** (bytes
/// 4--33), excluding the `ghp_` prefix. This difference in checksum scope
/// versus the fine-grained format is why both variants exist as separate
/// families.
fn gen_github_classic_pat(rng: &mut SimRng) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(b"ghp_");
    // 30 random base-62 payload chars
    for _ in 0..30 {
        let idx = rng.gen_range(0, 62) as usize;
        out.push(BASE62_CHARS[idx]);
    }
    debug_assert_eq!(out.len(), 34);
    // CRC-32 of payload only (prefix excluded)
    let crc = crc32fast::hash(&out[4..34]);
    let mut cksum = [0u8; 6];
    base62_encode_u32(crc, &mut cksum);
    out.extend_from_slice(&cksum);
    debug_assert_eq!(out.len(), 40);
    out
}

/// Generate a JWT-like token with three dot-separated base64url segments.
///
/// The header is fixed (`{"alg":"HS256"}`), producing the characteristic `eyJ`
/// prefix after base64url encoding. The payload contains a `sub` claim with 8
/// random alphanumeric characters. The signature is 32 random bytes. None of
/// the segments carry padding (`=`), per RFC 7515 section 2.
fn gen_jwt_like(rng: &mut SimRng) -> Vec<u8> {
    // Fixed header: {"alg":"HS256"}
    let header = base64url_encode_nopad(b"{\"alg\":\"HS256\"}");

    // Payload: {"sub":"<8 random alnum>"} — starts with eyJ
    let mut sub = [0u8; 8];
    for b in sub.iter_mut() {
        let idx = rng.gen_range(0, 36);
        *b = if idx < 10 {
            b'0' + idx as u8
        } else {
            b'a' + (idx - 10) as u8
        };
    }
    let mut payload_json = Vec::with_capacity(16 + sub.len());
    payload_json.extend_from_slice(b"{\"sub\":\"");
    payload_json.extend_from_slice(&sub);
    payload_json.extend_from_slice(b"\"}");
    let payload = base64url_encode_nopad(&payload_json);

    // Signature: 32 random bytes, base64url-encoded
    let mut sig_raw = [0u8; 32];
    for b in sig_raw.iter_mut() {
        *b = rng.gen_range(0, 256) as u8;
    }
    let signature = base64url_encode_nopad(&sig_raw);

    // Assemble: header.payload.signature
    let mut out = Vec::with_capacity(header.len() + 1 + payload.len() + 1 + signature.len());
    out.extend_from_slice(&header);
    out.push(b'.');
    out.extend_from_slice(&payload);
    out.push(b'.');
    out.extend_from_slice(&signature);
    out
}

/// Generate a base64-encoded blob of 24--48 random bytes.
///
/// The variable source length exercises the engine's entropy and length
/// heuristics across a range of output sizes (32--64 base64 characters).
fn gen_base64_blob(rng: &mut SimRng) -> Vec<u8> {
    let len = rng.gen_range(24, 49) as usize;
    let mut raw = vec![0u8; len];
    for b in raw.iter_mut() {
        *b = rng.gen_range(0, 256) as u8;
    }
    base64_encode_std(&raw)
}

/// Generate a percent-encoded blob of 16--32 random bytes.
///
/// Output length is 3x the source length (every byte becomes `%XX`), yielding
/// 48--96 characters.
fn gen_url_encoded_blob(rng: &mut SimRng) -> Vec<u8> {
    let len = rng.gen_range(16, 33) as usize;
    let mut raw = vec![0u8; len];
    for b in raw.iter_mut() {
        *b = rng.gen_range(0, 256) as u8;
    }
    percent_encode_all(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::mutation::encode::test_helpers::base62_decode;
    use crate::sim::rng::SimRng;

    #[test]
    fn determinism_all_families() {
        for family in TokenFamily::ALL {
            let a = family.gen_valid(&mut SimRng::new(42));
            let b = family.gen_valid(&mut SimRng::new(42));
            assert_eq!(a, b, "determinism failed for {family:?}");
        }
    }

    #[test]
    fn aws_access_key_format() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(99));
        assert_eq!(token.len(), 20);
        assert!(token.starts_with(b"AKIA"));
        for &b in &token[4..] {
            assert!(
                b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b),
                "invalid AWS base-32 char: {b:#x}",
            );
        }
    }

    #[test]
    fn github_fine_grained_pat_format_and_checksum() {
        let token = TokenFamily::GithubFinegrainedPat.gen_valid(&mut SimRng::new(7));
        assert_eq!(token.len(), 93);
        assert!(token.starts_with(b"github_pat_"));
        // Verify CRC: hash first 87 bytes, decode last 6.
        let expected_crc = crc32fast::hash(&token[..87]);
        let decoded_crc = base62_decode(&token[87..93]);
        assert_eq!(expected_crc, decoded_crc, "CRC-32 mismatch");
    }

    #[test]
    fn github_classic_pat_format_and_checksum() {
        let token = TokenFamily::GithubClassicPat.gen_valid(&mut SimRng::new(13));
        assert_eq!(token.len(), 40);
        assert!(token.starts_with(b"ghp_"));
        // CRC of payload only (bytes 4–33)
        let expected_crc = crc32fast::hash(&token[4..34]);
        let decoded_crc = base62_decode(&token[34..40]);
        assert_eq!(expected_crc, decoded_crc, "CRC-32 mismatch");
    }

    #[test]
    fn jwt_like_format() {
        let token = TokenFamily::JwtLike.gen_valid(&mut SimRng::new(21));
        let parts: Vec<&[u8]> = token.split(|&b| b == b'.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated segments");
        // Header starts with eyJ (base64url of '{"')
        assert!(parts[0].starts_with(b"eyJ"), "header must start with eyJ");
        // Payload starts with eyJ
        assert!(parts[1].starts_with(b"eyJ"), "payload must start with eyJ");
        // No padding chars
        assert!(!token.contains(&b'='), "JWT must not contain padding");
        assert!(!token.contains(&b'+'), "JWT must use - not +");
        assert!(!token.contains(&b'/'), "JWT must use _ not /");
    }

    #[test]
    fn base64_blob_is_valid_base64() {
        let token = TokenFamily::Base64Blob.gen_valid(&mut SimRng::new(55));
        // Should be valid base64 (all chars in standard alphabet + =)
        for &b in &token {
            assert!(
                b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=',
                "invalid base64 char: {b:#x}",
            );
        }
    }

    #[test]
    fn url_encoded_blob_format() {
        let token = TokenFamily::UrlEncodedBlob.gen_valid(&mut SimRng::new(77));
        // Must be %XX triples
        assert_eq!(
            token.len() % 3,
            0,
            "percent-encoded length must be multiple of 3"
        );
        for chunk in token.chunks(3) {
            assert_eq!(chunk[0], b'%');
            assert!(chunk[1].is_ascii_hexdigit());
            assert!(chunk[2].is_ascii_hexdigit());
        }
    }

    #[test]
    fn expectation_empty_ops_is_must_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &[]),
            Outcome::MustMatch,
        );
    }

    #[test]
    fn expectation_checksum_corrupt_on_crc_family() {
        let token = TokenFamily::GithubClassicPat.gen_valid(&mut SimRng::new(1));
        assert_eq!(
            TokenFamily::GithubClassicPat.expectation(&token, &[MutOp::ChecksumCorrupt]),
            Outcome::MustNotMatch,
        );
    }

    #[test]
    fn expectation_prefix_mangle_is_must_not_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(
                &token,
                &[MutOp::PrefixMangle {
                    replacement: b"XXXX".to_vec(),
                }]
            ),
            Outcome::MustNotMatch,
        );
    }

    #[test]
    fn allowed_ops_excludes_checksum_for_aws() {
        let ops = TokenFamily::AwsAccessKey.allowed_ops();
        assert!(!ops.contains(&MutOpKind::ChecksumCorrupt));
    }

    #[test]
    fn allowed_ops_includes_checksum_for_github() {
        assert!(TokenFamily::GithubFinegrainedPat
            .allowed_ops()
            .contains(&MutOpKind::ChecksumCorrupt));
        assert!(TokenFamily::GithubClassicPat
            .allowed_ops()
            .contains(&MutOpKind::ChecksumCorrupt));
    }

    /// Verify that generated AWS keys have account IDs within the engine's
    /// accepted range (≤ 999_999_999_999). If the generator picks random
    /// base-32 chars without constraining the decoded 40-bit account ID,
    /// some seeds will produce keys the engine rejects as invalid.
    #[test]
    fn aws_account_id_within_valid_range() {
        // Decode 16 base-32 chars into the embedded 40-bit account ID,
        // mirroring the logic in engine/offline_validate.rs.
        fn decode_account_id(suffix: &[u8]) -> Option<u64> {
            if suffix.len() != 16 {
                return None;
            }
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
            let raw_40 = ((decoded[0] as u64 & 0x7F) << 33)
                | ((decoded[1] as u64) << 25)
                | ((decoded[2] as u64) << 17)
                | ((decoded[3] as u64) << 9)
                | ((decoded[4] as u64) << 1)
                | ((decoded[5] as u64) >> 7);
            Some(raw_40)
        }

        // Test 200 seeds — with ~9% failure rate on unconstrained random
        // base-32 chars, this should catch the bug reliably.
        for seed in 0..200u64 {
            let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(seed));
            let suffix = &token[4..20];
            let account_id = decode_account_id(suffix)
                .unwrap_or_else(|| panic!("seed {seed}: failed to decode base-32 suffix"));
            assert!(
                account_id <= 999_999_999_999,
                "seed {seed}: account ID {account_id} exceeds 999_999_999_999",
            );
        }
    }

    /// Verify that the expectation oracle handles chained operators correctly.
    /// A soft op (Extend) followed by a hard breaker (Truncate below canonical
    /// length) should produce MustNotMatch, not MayMatch.
    #[test]
    fn expectation_extend_then_truncate_below_canonical() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        assert_eq!(token.len(), 20);

        // Extend by 1 byte, then truncate to 5 — well below canonical length.
        // apply_ops produces a 5-byte token which definitively cannot match.
        let ops = vec![
            MutOp::Extend { suffix: vec![0] },
            MutOp::Truncate { len: 5 },
        ];
        let outcome = TokenFamily::AwsAccessKey.expectation(&token, &ops);
        assert_eq!(
            outcome,
            Outcome::MustNotMatch,
            "extend+truncate below canonical length should be MustNotMatch",
        );
    }

    // -- Oracle path coverage --

    #[test]
    fn oracle_truncate_below_canonical_is_must_not_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        let ops = vec![MutOp::Truncate { len: 5 }];
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &ops),
            Outcome::MustNotMatch,
        );
    }

    #[test]
    fn oracle_truncate_at_canonical_len_is_must_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        let ops = vec![MutOp::Truncate {
            len: token.len() + 10,
        }];
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &ops),
            Outcome::MustMatch,
        );
    }

    #[test]
    fn oracle_charset_violate_in_range_is_must_not_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        let ops = vec![MutOp::CharsetViolate {
            positions: vec![0],
            replacement: 0xFF,
        }];
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &ops),
            Outcome::MustNotMatch,
        );
    }

    #[test]
    fn oracle_charset_violate_out_of_range_is_must_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        let ops = vec![MutOp::CharsetViolate {
            positions: vec![999],
            replacement: 0xFF,
        }];
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &ops),
            Outcome::MustMatch,
        );
    }

    #[test]
    fn oracle_checksum_corrupt_non_crc_family_is_may_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &[MutOp::ChecksumCorrupt]),
            Outcome::MayMatch,
        );
    }

    #[test]
    fn oracle_entropy_reduce_zero_count_is_must_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        let ops = vec![MutOp::EntropyReduce {
            repeat_byte: b'A',
            count: 0,
        }];
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &ops),
            Outcome::MustMatch,
        );
    }

    #[test]
    fn oracle_entropy_reduce_nonzero_count_is_may_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        let ops = vec![MutOp::EntropyReduce {
            repeat_byte: b'A',
            count: 5,
        }];
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &ops),
            Outcome::MayMatch,
        );
    }

    #[test]
    fn oracle_encode_is_may_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        let ops = vec![MutOp::Encode {
            repr: super::super::encode::SecretRepr::Base64,
        }];
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &ops),
            Outcome::MayMatch,
        );
    }

    #[test]
    fn oracle_extend_empty_suffix_is_must_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        let ops = vec![MutOp::Extend { suffix: vec![] }];
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &ops),
            Outcome::MustMatch,
        );
    }

    #[test]
    fn oracle_extend_nonempty_suffix_is_may_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        let ops = vec![MutOp::Extend { suffix: vec![0xAB] }];
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &ops),
            Outcome::MayMatch,
        );
    }

    #[test]
    fn token_family_rule_id_matches_all_index() {
        for (i, family) in TokenFamily::ALL.iter().enumerate() {
            assert_eq!(
                family.rule_id(),
                i as u32,
                "{family:?}.rule_id() does not match its index in ALL",
            );
        }
    }

    #[test]
    fn oracle_prefix_mangle_empty_replacement_is_must_match() {
        let token = TokenFamily::AwsAccessKey.gen_valid(&mut SimRng::new(1));
        let ops = vec![MutOp::PrefixMangle {
            replacement: vec![],
        }];
        assert_eq!(
            TokenFamily::AwsAccessKey.expectation(&token, &ops),
            Outcome::MustMatch,
        );
    }
}
