//! Start set configuration and deterministic identity.
//!
//! A start set defines which refs are selected for scanning. The identity
//! (`StartSetId`) is a 32-byte BLAKE3 hash of a canonical, versioned encoding
//! of the configuration structure, not the resolved ref set.
//!
//! # Identity Semantics
//!
//! The identity hashes the config, not the refs it resolves to:
//! - `DefaultBranchOnly` and `ExplicitRefs { refs: vec![b"refs/heads/main"] }`
//!   produce different ids even if they resolve to the same ref.
//! - This is intentional: dynamic selectors like `AllRemoteBranches` would
//!   churn the id as branches appear or disappear, forcing unnecessary rescans.
//! - `ExplicitRefs` is order-invariant and duplicate-invariant (sorted and
//!   deduped before hashing).
//! - All other variants are field-invariant (hashed in canonical order).
//!
//! # Stability
//!
//! Ids are stable across process restarts and platforms (deterministic
//! encoding, explicit endianness). They are stable across software versions
//! only as long as `VERSION` and encoding semantics remain unchanged.
//! Bumping `VERSION` intentionally invalidates all existing ids, forcing
//! a full rescan. This is the correct behavior when identity semantics change.

/// 32-byte stable identity for a start set configuration.
///
/// Derived from BLAKE3 over canonical versioned encoding of the config
/// structure. Used as part of the watermark key:
/// `(repo_id, policy_hash, start_set_id, ref_name)`.
pub type StartSetId = [u8; 32];

/// Start set configuration used to select which refs define scan coverage.
///
/// This stays small and explicit. If you want complex logic, resolve refs
/// externally and use `ExplicitRefs`.
///
/// # Identity Contract
///
/// `config.id()` produces a deterministic 32-byte hash of the config
/// structure. Two configs with the same canonical encoding produce the
/// same id. Specifically:
/// - `ExplicitRefs` is order-invariant and duplicate-invariant
/// - All other variants are field-invariant
/// - The encoding is versioned; bumping `VERSION` invalidates all ids
/// - Different variant types always produce different ids, even if they
///   would resolve to identical refs at runtime
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartSetConfig {
    /// Scan only the default branch (resolved via symbolic HEAD in resolver).
    DefaultBranchOnly,

    /// Scan all remote branches. Optional remote filter (e.g., `b"origin"`).
    AllRemoteBranches {
        /// If `Some`, only branches under this remote. If `None`, all remotes.
        remote: Option<Vec<u8>>,
    },

    /// Scan local branches plus tags. Optionally also include remote branches.
    BranchesAndTags {
        /// Whether to also include remote tracking branches.
        include_remote_branches: bool,
        /// If `Some`, only remote branches under this remote.
        remote: Option<Vec<u8>>,
    },

    /// Exact explicit fully-qualified refs (e.g., `b"refs/heads/main"`).
    ///
    /// Identity is order-invariant and duplicate-invariant: refs are sorted
    /// and deduped before hashing.
    ExplicitRefs {
        /// Fully-qualified ref names.
        refs: Vec<Vec<u8>>,
    },
}

impl StartSetConfig {
    /// Encoding version. Bump this to invalidate all existing start set ids.
    const VERSION: u8 = 1;

    /// Computes the deterministic 32-byte identity for this configuration.
    ///
    /// Called once per job in repo open, not a hot path.
    ///
    /// # Panics
    ///
    /// Panics if any ref name in `ExplicitRefs` exceeds `u16::MAX` bytes.
    /// This cannot happen when refs pass through `RepoOpenLimits` validation
    /// (default max: 1024 bytes), so this is defense-in-depth.
    #[must_use]
    pub fn id(&self) -> StartSetId {
        let mut buf = Vec::with_capacity(256);
        self.encode_canonical(&mut buf);

        debug_assert!(!buf.is_empty(), "canonical encoding must be non-empty");

        *blake3::hash(&buf).as_bytes()
    }

    /// Canonical encoding for stable identity hashing.
    ///
    /// Format:
    /// - prefix: `b"start_set\0"` (10 bytes, domain separator)
    /// - version: `u8`
    /// - variant tag: `u8`
    /// - variant payload (length-prefixed where variable)
    ///
    /// # Invariants
    ///
    /// - `out` is cleared before encoding (caller does not need to clear)
    /// - For `ExplicitRefs`: refs are sorted and deduped before encoding
    /// - All multi-byte integers are little-endian
    /// - Ref name count is encoded as u32; individual lengths as u16
    pub(crate) fn encode_canonical(&self, out: &mut Vec<u8>) {
        out.clear();

        // Domain separator prevents cross-type collisions.
        out.extend_from_slice(b"start_set");
        out.push(0);
        out.push(Self::VERSION);

        match self {
            StartSetConfig::DefaultBranchOnly => {
                out.push(1);
            }
            StartSetConfig::AllRemoteBranches { remote } => {
                out.push(2);
                encode_opt_bytes(out, remote.as_deref());
            }
            StartSetConfig::BranchesAndTags {
                include_remote_branches,
                remote,
            } => {
                out.push(3);
                out.push(u8::from(*include_remote_branches));
                encode_opt_bytes(out, remote.as_deref());
            }
            StartSetConfig::ExplicitRefs { refs } => {
                out.push(4);

                // Sort and dedup a slice view for order/duplicate invariance.
                // No data cloning; only slice references are copied, not the underlying bytes.
                let mut v: Vec<&[u8]> = refs.iter().map(|r| r.as_slice()).collect();
                v.sort_unstable();
                v.dedup();

                assert!(
                    v.len() <= u32::MAX as usize,
                    "too many explicit refs for encoding: {}",
                    v.len()
                );
                push_u32_le(out, v.len() as u32);
                for r in v {
                    push_bytes_u16(out, r);
                }
            }
        }
    }
}

/// Encodes an optional byte slice: 0x00 for None, 0x01 + length-prefixed for Some.
fn encode_opt_bytes(out: &mut Vec<u8>, b: Option<&[u8]>) {
    match b {
        None => out.push(0),
        Some(x) => {
            out.push(1);
            push_bytes_u16(out, x);
        }
    }
}

/// Appends a u32 in little-endian.
fn push_u32_le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Appends a u16 in little-endian.
fn push_u16_le(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// Appends a length-prefixed byte slice (u16 length, little-endian).
///
/// # Panics
///
/// Panics if `b.len() > u16::MAX`. Ref names exceeding 64 KiB are rejected
/// earlier by `RepoOpenLimits::max_refname_bytes` (default: 1024, max: u16),
/// so this is a defense-in-depth assertion, not a user-facing error.
fn push_bytes_u16(out: &mut Vec<u8>, b: &[u8]) {
    assert!(
        b.len() <= u16::MAX as usize,
        "byte slice too long for u16 prefix: {}",
        b.len()
    );
    push_u16_le(out, b.len() as u16);
    out.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_refs_id_is_order_invariant_and_duplicate_invariant() {
        let a = StartSetConfig::ExplicitRefs {
            refs: vec![b"refs/heads/b".to_vec(), b"refs/heads/a".to_vec()],
        };
        let b = StartSetConfig::ExplicitRefs {
            refs: vec![
                b"refs/heads/a".to_vec(),
                b"refs/heads/b".to_vec(),
                b"refs/heads/a".to_vec(),
            ],
        };
        assert_eq!(a.id(), b.id());
    }

    #[test]
    fn different_variants_produce_different_ids() {
        let a = StartSetConfig::DefaultBranchOnly;
        let b = StartSetConfig::AllRemoteBranches { remote: None };
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn same_variant_different_remote_produces_different_ids() {
        let a = StartSetConfig::AllRemoteBranches {
            remote: Some(b"origin".to_vec()),
        };
        let b = StartSetConfig::AllRemoteBranches {
            remote: Some(b"upstream".to_vec()),
        };
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn remote_none_vs_some_produces_different_ids() {
        let a = StartSetConfig::AllRemoteBranches { remote: None };
        let b = StartSetConfig::AllRemoteBranches {
            remote: Some(b"origin".to_vec()),
        };
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn branches_and_tags_flag_matters() {
        let a = StartSetConfig::BranchesAndTags {
            include_remote_branches: false,
            remote: None,
        };
        let b = StartSetConfig::BranchesAndTags {
            include_remote_branches: true,
            remote: None,
        };
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn branches_and_tags_remote_none_vs_some() {
        let a = StartSetConfig::BranchesAndTags {
            include_remote_branches: true,
            remote: None,
        };
        let b = StartSetConfig::BranchesAndTags {
            include_remote_branches: true,
            remote: Some(b"origin".to_vec()),
        };
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn some_empty_vs_none_produces_different_ids() {
        // None encodes as 0x00; Some(b"") encodes as 0x01 0x00 0x00.
        // These must differ: None = all remotes, Some(b"") = empty remote name.
        let a = StartSetConfig::AllRemoteBranches { remote: None };
        let b = StartSetConfig::AllRemoteBranches {
            remote: Some(b"".to_vec()),
        };
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn id_is_deterministic_across_calls() {
        let cfg = StartSetConfig::ExplicitRefs {
            refs: vec![b"refs/heads/main".to_vec(), b"refs/heads/develop".to_vec()],
        };
        let id1 = cfg.id();
        let id2 = cfg.id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn empty_explicit_refs_has_stable_id() {
        let cfg = StartSetConfig::ExplicitRefs { refs: vec![] };
        let id1 = cfg.id();
        let id2 = cfg.id();
        assert_eq!(id1, id2);
        assert_ne!(id1, StartSetConfig::DefaultBranchOnly.id());
    }

    #[test]
    fn canonical_encoding_clears_buffer() {
        let mut buf = vec![0xff; 100];
        StartSetConfig::DefaultBranchOnly.encode_canonical(&mut buf);
        assert!(buf.starts_with(b"start_set"));
    }

    #[test]
    fn canonical_encoding_layout_regression() {
        let mut buf = Vec::new();
        StartSetConfig::DefaultBranchOnly.encode_canonical(&mut buf);

        assert_eq!(buf.len(), 12);
        assert_eq!(&buf[0..9], b"start_set");
        assert_eq!(buf[9], 0x00);
        assert_eq!(buf[10], 1);
        assert_eq!(buf[11], 1);
    }

    #[test]
    fn canonical_encoding_explicit_refs_layout() {
        let mut buf = Vec::new();
        let cfg = StartSetConfig::ExplicitRefs {
            refs: vec![b"ab".to_vec(), b"cd".to_vec()],
        };
        cfg.encode_canonical(&mut buf);

        assert_eq!(buf[11], 4);
        assert_eq!(&buf[12..16], &2u32.to_le_bytes());
        assert_eq!(&buf[16..18], &2u16.to_le_bytes());
        assert_eq!(&buf[18..20], b"ab");
        assert_eq!(&buf[20..22], &2u16.to_le_bytes());
        assert_eq!(&buf[22..24], b"cd");
        assert_eq!(buf.len(), 24);
    }

    #[test]
    fn encode_opt_bytes_none_vs_some_empty_differ_in_encoding() {
        let mut buf_none = Vec::new();
        let mut buf_some_empty = Vec::new();

        StartSetConfig::AllRemoteBranches { remote: None }.encode_canonical(&mut buf_none);
        StartSetConfig::AllRemoteBranches {
            remote: Some(b"".to_vec()),
        }
        .encode_canonical(&mut buf_some_empty);

        assert!(buf_none.len() < buf_some_empty.len());
        assert_ne!(buf_none, buf_some_empty);
    }
}
