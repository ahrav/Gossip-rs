//! Policy hash canonicalization for Git scanning.
//!
//! Incremental Git scans persist watermarks keyed by
//! `(repo_id, policy_hash, start_set_id, ref_name)` and seen-blob sets
//! keyed by `(repo_id, policy_hash, oid)`. When the scanning
//! policy changes -- different rules, different tuning, different merge
//! strategy -- cached state is no longer valid: a blob marked "seen" under
//! the old policy may produce different findings under the new one. The
//! policy hash detects these changes so the pipeline can discard stale
//! caches and force a full rescan.
//!
//! The hash is a BLAKE3 digest over a canonical byte encoding of:
//! - **Rule specs** (canonicalized and order-invariant)
//! - **Transform configs** (order-preserving, since pipeline order matters)
//! - **Tuning parameters**
//! - **Merge diff mode**
//!
//! # Encoding format
//!
//! The byte stream is a sequence of tagged sections. Each section starts
//! with an ASCII tag name, a null separator byte, and the section payload.
//! The first section carries the format version so that any structural
//! change to the encoding (new sections, reordered fields) can be made
//! unambiguously by bumping [`POLICY_HASH_VERSION`].
//!
//! This format is write-only: the output is never parsed, only hashed.
//!
//! # Fields deliberately excluded
//!
//! `RuleSpec::local_context`, `RuleSpec::uuid_format_secret`, and
//! `RuleSpec::min_confidence` are not encoded by
//! [`RuleSpec::encode_policy`](scanner_engine::RuleSpec). These fields affect
//! post-extraction suppression/thresholding rather than core detection
//! (anchor matching, window construction, regex evaluation), so changing
//! them is accepted as a minor staleness trade-off rather than forcing a
//! full rescan.
//!
//! # Invariants
//! - Identical inputs yield identical hashes across platforms and runs.
//! - Rule ordering does not affect the hash (rules are sorted after
//!   individual encoding).
//! - Any change in the fields encoded by `encode_policy` produces a
//!   distinct byte stream, yielding a different hash with overwhelming
//!   probability.
//! - Bumping `POLICY_HASH_VERSION` invalidates all previous hashes,
//!   forcing full rescans.

use scanner_engine::{RuleSpec, TransformConfig, Tuning};

/// 32-byte BLAKE3 digest that uniquely identifies a Git scanning policy.
///
/// Flows into watermark keys and seen-blob keys in the persistence layer
/// (see [`RocksDbStore`](super::persist_rocksdb::RocksDbStore) and
/// [`RefWatermarkStore`](super::repo_open::RefWatermarkStore)), ensuring
/// that cached scan state is scoped to the exact policy that produced it.
pub type PolicyHash = [u8; 32];

/// Merge diff strategy applied during commit traversal.
///
/// Controls how the tree-diff stage handles merge commits, which have
/// multiple parents. The choice affects which blobs are considered
/// "introduced" by a merge and therefore need scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeDiffMode {
    /// Diff against every parent and union the resulting blob changes.
    ///
    /// Catches blobs that differ from *any* parent, including evil-merge
    /// content that does not appear in any parent tree. More thorough but
    /// produces more candidates on merge-heavy histories.
    AllParents,
    /// Diff against the first parent only, ignoring side-branch trees.
    ///
    /// Follows the mainline perspective: only blobs new relative to the
    /// first parent are scanned. Faster on repositories with frequent
    /// merges, at the cost of missing evil-merge content.
    FirstParentOnly,
}

impl MergeDiffMode {
    /// Appends a single-byte discriminant tag to `out`.
    ///
    /// Tags start at 1 (not 0) so that a missing or zero byte is never
    /// a valid mode, making accidental collisions with padding impossible.
    #[inline]
    fn encode(self, out: &mut Vec<u8>) {
        let tag = match self {
            MergeDiffMode::AllParents => 1,
            MergeDiffMode::FirstParentOnly => 2,
        };
        out.push(tag);
    }
}

/// Format version embedded at the start of the encoded byte stream.
///
/// Bump this whenever the encoding layout changes (new sections, reordered
/// fields, changed width of an existing field). Because the version byte
/// is part of the hashed input, a bump automatically invalidates every
/// previously computed policy hash, forcing full rescans across all
/// repositories.
const POLICY_HASH_VERSION: u8 = 1;

/// Computes the canonical policy hash for a Git scanning configuration.
///
/// The returned 32-byte digest should be stored in
/// [`GitScanConfig::policy_hash`](super::runner::GitScanConfig::policy_hash)
/// so the pipeline can scope watermarks and seen-blob keys to this exact
/// policy.
///
/// # Ordering guarantees
/// - `rules` are **order-invariant**: reordering the slice does not change
///   the hash. Each rule is encoded independently, and the resulting byte
///   blobs are lexicographically sorted before hashing.
/// - `transforms` are **order-preserving**: swapping two transforms
///   changes the hash, because pipeline order determines decode semantics.
/// - `tuning` and `merge_diff_mode` are included verbatim.
///
/// # What is (and is not) encoded
///
/// Each component delegates to its `encode_policy` method in
/// [`crate::api`]. Fields that do not affect finding detection
/// (`local_context`, `uuid_format_secret`, `min_confidence`) are
/// deliberately excluded; see the module-level docs for rationale.
#[must_use]
pub fn policy_hash(
    rules: &[RuleSpec],
    transforms: &[TransformConfig],
    tuning: &Tuning,
    merge_diff_mode: MergeDiffMode,
) -> PolicyHash {
    let mut buf = Vec::with_capacity(4096);
    encode_policy_hash(&mut buf, rules, transforms, tuning, merge_diff_mode);

    *blake3::hash(&buf).as_bytes()
}

/// Serializes the full policy into a canonical byte stream in `out`.
///
/// The stream is structured as a sequence of tagged sections:
///
/// ```text
/// b"policy_hash" NUL <version>
/// b"merge_diff"  NUL <mode-tag>
/// b"tuning"      NUL <tuning-payload>
/// b"transforms"  NUL <transforms-payload>
/// b"rules"       NUL <rules-payload>
/// ```
///
/// ASCII tag names followed by a NUL separator make accidental collisions
/// between adjacent sections impossible without requiring length prefixes
/// at the section level. The version byte at the top ensures that any
/// structural change to this layout produces a completely different hash.
fn encode_policy_hash(
    out: &mut Vec<u8>,
    rules: &[RuleSpec],
    transforms: &[TransformConfig],
    tuning: &Tuning,
    merge_diff_mode: MergeDiffMode,
) {
    out.clear();

    out.extend_from_slice(b"policy_hash");
    out.push(0);
    out.push(POLICY_HASH_VERSION);

    out.extend_from_slice(b"merge_diff");
    out.push(0);
    merge_diff_mode.encode(out);

    out.extend_from_slice(b"tuning");
    out.push(0);
    tuning.encode_policy(out);

    out.extend_from_slice(b"transforms");
    out.push(0);
    encode_transforms(out, transforms);

    out.extend_from_slice(b"rules");
    out.push(0);
    encode_rules(out, rules);
}

/// Encodes rules in a canonical, order-invariant form.
///
/// Each rule is encoded into its own byte buffer via
/// [`RuleSpec::encode_policy`](scanner_engine::RuleSpec), and the resulting
/// buffers are lexicographically sorted before being concatenated. This
/// "encode-then-sort" approach avoids requiring a canonical ordering on
/// `RuleSpec` itself while still guaranteeing that `{A, B}` and `{B, A}`
/// produce identical output.
///
/// The wire layout is:
/// ```text
/// <rule-count: u32-le> ( <blob-len: u32-le> <blob-bytes> )*
/// ```
fn encode_rules(out: &mut Vec<u8>, rules: &[RuleSpec]) {
    let mut encoded = Vec::with_capacity(rules.len());
    for rule in rules {
        let mut buf = Vec::new();
        rule.encode_policy(&mut buf);
        encoded.push(buf);
    }
    encoded.sort_unstable();

    push_u32_le(out, encoded.len() as u32);
    for bytes in encoded {
        push_u32_le(out, bytes.len() as u32);
        out.extend_from_slice(&bytes);
    }
}

/// Encodes transforms in a stable, order-preserving form.
///
/// Unlike rules, transform order is significant: `[URL, Base64]` and
/// `[Base64, URL]` define different decode pipelines and must produce
/// different hashes. Transforms are written sequentially with a leading
/// count but no per-element sorting.
fn encode_transforms(out: &mut Vec<u8>, transforms: &[TransformConfig]) {
    push_u32_le(out, transforms.len() as u32);
    for transform in transforms {
        transform.encode_policy(out);
    }
}

/// Appends a little-endian `u32` to the buffer (length prefix helper).
fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::Regex;
    use scanner_engine::demo_tuning;
    use scanner_engine::{Gate, TransformId, TransformMode};

    fn rule(name: &'static str, pattern: &str, anchors: &'static [&'static [u8]]) -> RuleSpec {
        RuleSpec {
            name,
            anchors,
            radius: 64,
            validator: scanner_engine::ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: None,
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re: Regex::new(pattern).unwrap(),
        }
    }

    fn transforms() -> Vec<TransformConfig> {
        vec![TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 8,
            max_encoded_len: 256,
            max_decoded_bytes: 256,
            plus_to_space: false,
            base64_allow_space_ws: false,
        }]
    }

    #[test]
    fn policy_hash_is_stable() {
        let rules = vec![rule("a", "a", &[b"a"]), rule("b", "b", &[b"b"])];
        let tuning = demo_tuning();
        let h1 = policy_hash(&rules, &transforms(), &tuning, MergeDiffMode::AllParents);
        let h2 = policy_hash(&rules, &transforms(), &tuning, MergeDiffMode::AllParents);
        assert_eq!(h1, h2);
    }

    #[test]
    fn policy_hash_is_sensitive_to_value_suppressors_any() {
        let mut r1 = rule("a", "a", &[b"a"]);
        let mut r2 = rule("a", "a", &[b"a"]);
        r1.value_suppressors_any = None;
        r2.value_suppressors_any = Some(&[b"EXAMPLE"]);
        let tuning = demo_tuning();

        let h1 = policy_hash(&[r1], &transforms(), &tuning, MergeDiffMode::AllParents);
        let h2 = policy_hash(&[r2], &transforms(), &tuning, MergeDiffMode::AllParents);
        assert_ne!(
            h1, h2,
            "changing value_suppressors_any must change the policy hash"
        );
    }

    #[test]
    fn encode_policy_excludes_min_confidence_threshold() {
        let mut left = rule("a", "a", &[b"a"]);
        let mut right = rule("a", "a", &[b"a"]);
        left.min_confidence = None;
        right.min_confidence = Some(5);

        let mut left_bytes = Vec::new();
        let mut right_bytes = Vec::new();
        left.encode_policy(&mut left_bytes);
        right.encode_policy(&mut right_bytes);

        assert_eq!(
            left_bytes, right_bytes,
            "changing min_confidence should not change rule policy encoding"
        );
    }

    #[test]
    fn policy_hash_is_sensitive_to_digit_penalty() {
        let mut r1 = rule("a", "a", &[b"a"]);
        let mut r2 = rule("a", "a", &[b"a"]);
        r1.entropy = Some(scanner_engine::EntropySpec {
            min_bits_per_byte: 3.0,
            min_len: 8,
            max_len: 64,
            min_entropy_bits_per_byte: None,
            digit_penalty: false,
        });
        r2.entropy = Some(scanner_engine::EntropySpec {
            min_bits_per_byte: 3.0,
            min_len: 8,
            max_len: 64,
            min_entropy_bits_per_byte: None,
            digit_penalty: true,
        });
        let tuning = demo_tuning();

        let h1 = policy_hash(&[r1], &transforms(), &tuning, MergeDiffMode::AllParents);
        let h2 = policy_hash(&[r2], &transforms(), &tuning, MergeDiffMode::AllParents);
        assert_ne!(h1, h2, "changing digit_penalty must change the policy hash");
    }

    #[test]
    fn policy_hash_is_order_invariant_for_rules() {
        let r1 = rule("a", "a", &[b"a"]);
        let r2 = rule("b", "b", &[b"b"]);
        let tuning = demo_tuning();

        let h1 = policy_hash(
            &[r1.clone(), r2.clone()],
            &transforms(),
            &tuning,
            MergeDiffMode::AllParents,
        );
        let h2 = policy_hash(&[r2, r1], &transforms(), &tuning, MergeDiffMode::AllParents);
        assert_eq!(h1, h2);
    }
}
