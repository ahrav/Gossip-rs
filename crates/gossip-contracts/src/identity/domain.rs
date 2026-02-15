//! Authoritative domain-separation constant registry.
//!
//! Every domain tag used across all five boundary layers is defined here
//! exactly once. Domain separation prevents cross-derivation collisions:
//! `blake3("gossip/finding/v1", data)` and
//! `blake3("gossip/occurrence/v1", data)` are independent hash domains.
//! Cross-domain collisions are cryptographically negligible, not impossible.
//!
//! # Naming convention
//!
//! All tags follow the pattern `"gossip/<subsystem>/v<N>[/<operation>]"`:
//! - `<subsystem>` identifies the logical owner (coord, finding, persistence, …).
//! - `v<N>` is a monotonically increasing scheme version.
//! - `<operation>` is present when the subsystem owns multiple derivations.
//!
//! # Hash mode
//!
//! Most constants are used with [`domain_hasher`] which invokes BLAKE3
//! derive-key mode (`Hasher::new_derive_key`). The one exception is
//! [`SECRET_HASH_V1`], which is fed as data into a BLAKE3 keyed-mode hasher
//! (`Hasher::new_keyed`) in the planned Phase 1 secret-hash derivation path.
//!
//! # Safety requirements
//!
//! - Every constant **must** be valid UTF-8 (ASCII expected) because
//!   [`domain_hasher`] converts `&[u8]` to `&str` via `expect`.
//! - No two constants may share the same byte value. The `no_duplicate_values`
//!   test enforces this at `cargo test` time.
//! - Constants are `&[u8]` (not `&str`) to avoid a redundant conversion
//!   at every call site; the UTF-8 check happens inside `domain_hasher`.
//!
//! [`domain_hasher`]: super::domain_hasher

// =========================================================================
// Coordination subsystem
// =========================================================================

/// Shard-ID derivation during split operations.
///
/// Planned call site (Phase 1 coordination): shard split-ID derivation.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const SPLIT_ID_V1: &[u8] = b"gossip/coord/v1/split-id";

/// Op-log payload hashing for idempotency conflict detection.
///
/// Planned call site (Phase 1 coordination): operation payload hash for
/// idempotency conflict detection.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const OP_PAYLOAD_V1: &[u8] = b"gossip/coord/v1/op-payload";

// =========================================================================
// Identity subsystem — finding & secret derivations
// =========================================================================

/// `FindingId` derivation from `(tenant, item, rule, secret_hash)`.
///
/// Planned call site (Phase 1 identity): finding-ID derivation.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const FINDING_ID_V1: &[u8] = b"gossip/finding/v1";

/// `OccurrenceId` derivation from `(finding, version, offset, length)`.
///
/// Planned call site (Phase 1 identity): occurrence-ID derivation.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const OCCURRENCE_ID_V1: &[u8] = b"gossip/occurrence/v1";

/// `SecretHash` keying — tenant-scoped secret identity.
///
/// Planned call site (Phase 1 identity): secret-hash keyed derivation.
/// Hash mode: **BLAKE3 keyed mode** (`Hasher::new_keyed`). The domain tag is
/// fed as data *inside* the keyed hasher, not as a derive-key context.
pub const SECRET_HASH_V1: &[u8] = b"gossip/secret-hash/v1";

/// `StableItemId` derivation from `ItemKey`.
///
/// Planned call site (Phase 1 identity): stable item-ID derivation.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const ITEM_ID_V1: &[u8] = b"gossip/item-id/v1";

/// `ObjectVersionId` derivation from version bytes.
///
/// Planned call site (Phase 1 identity): object-version-ID derivation.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const OBJECT_VERSION_V1: &[u8] = b"gossip/object-version/v1";

/// `RuleFingerprint` derivation from rule definition.
///
/// Planned call site: engine-side rule fingerprinting (outside this crate).
/// Domain tag provided here for registry completeness and uniqueness enforcement.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const RULE_FINGERPRINT_V1: &[u8] = b"gossip/rule/v1";

// =========================================================================
// Policy subsystem
// =========================================================================

/// `PolicyHash` derivation from `PolicyHashInputs`.
///
/// Planned call site (Phase 1 policy hashing): `PolicyHash` computation.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
///
/// Note: version is `v2` because the derivation scheme was redesigned after
/// the initial spec (v1 was never shipped).
pub const POLICY_HASH_V2: &[u8] = b"gossip/policy-hash/v2";

/// Rules-digest derivation — content-addressed hash of the full rule set.
///
/// Planned call site: engine-side rules digest computation (outside this crate).
/// Domain tag provided here for registry completeness and uniqueness enforcement.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const RULES_DIGEST_V1: &[u8] = b"gossip/rules-digest/v1";

// =========================================================================
// Persistence subsystem
// =========================================================================

/// OVID (Object-Version Identity) hash derivation.
///
/// Planned call site (Phase 1 persistence): OVID derivation.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const OVID_V1: &[u8] = b"gossip/persistence/v1/ovid";

/// Done-ledger key derivation.
///
/// Reserved for future use — will be needed if the done-ledger key requires
/// hashing beyond simple field concatenation.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const DONE_LEDGER_KEY_V1: &[u8] = b"gossip/persistence/v1/done-key";

/// `TriageGroupKey` derivation from `(tenant, item)`.
///
/// Planned call site (Phase 1 persistence): triage-group key derivation.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const TRIAGE_GROUP_KEY_V1: &[u8] = b"gossip/persistence/v1/triage-group";

// =========================================================================
// Test fixtures
// =========================================================================

/// Returns every domain constant in the registry as a `(name, value)` pair.
///
/// Used by the uniqueness and coverage tests in this module.
/// When adding a new domain constant, you **must** add it here *and*
/// bump `expected_count` in `fixture_covers_all_module_constants`.
#[cfg(test)]
pub(crate) fn all_domain_constants() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("SPLIT_ID_V1", SPLIT_ID_V1),
        ("OP_PAYLOAD_V1", OP_PAYLOAD_V1),
        ("FINDING_ID_V1", FINDING_ID_V1),
        ("OCCURRENCE_ID_V1", OCCURRENCE_ID_V1),
        ("SECRET_HASH_V1", SECRET_HASH_V1),
        ("ITEM_ID_V1", ITEM_ID_V1),
        ("OBJECT_VERSION_V1", OBJECT_VERSION_V1),
        ("RULE_FINGERPRINT_V1", RULE_FINGERPRINT_V1),
        ("POLICY_HASH_V2", POLICY_HASH_V2),
        ("RULES_DIGEST_V1", RULES_DIGEST_V1),
        ("OVID_V1", OVID_V1),
        ("DONE_LEDGER_KEY_V1", DONE_LEDGER_KEY_V1),
        ("TRIAGE_GROUP_KEY_V1", TRIAGE_GROUP_KEY_V1),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn all_constants_are_printable_ascii() {
        for (name, value) in all_domain_constants() {
            for (i, &byte) in value.iter().enumerate() {
                assert!(
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'/'
                        || byte == b'-',
                    "domain constant {name} has disallowed byte 0x{byte:02X} \
                     at position {i}: {:?}",
                    core::str::from_utf8(value).unwrap_or("<invalid>")
                );
            }
        }
    }

    #[test]
    fn all_constants_follow_naming_convention() {
        for (name, value) in all_domain_constants() {
            let s = core::str::from_utf8(value).unwrap();

            assert!(
                s.starts_with("gossip/"),
                "domain constant {name} does not start with 'gossip/': {s}"
            );

            // Subsystem segment must be non-empty.
            let after_prefix = &s["gossip/".len()..];
            let next_slash = after_prefix.find('/').unwrap_or(after_prefix.len());
            assert!(
                next_slash > 0,
                "domain constant {name} has empty subsystem segment: {s}"
            );

            // Version marker: "/v" followed by digit(s), then end-of-string or '/'.
            let has_valid_version = s.match_indices("/v").any(|(pos, _)| {
                let after_v = &s[pos + 2..];
                let digit_count = after_v.chars().take_while(|c| c.is_ascii_digit()).count();
                digit_count > 0
                    && (digit_count == after_v.len() || after_v.as_bytes()[digit_count] == b'/')
            });
            assert!(
                has_valid_version,
                "domain constant {name} missing valid version marker '/v<digit>': {s}"
            );

            assert!(
                !s.ends_with('/'),
                "domain constant {name} has trailing slash: {s}"
            );
        }
    }

    #[test]
    fn all_constants_have_reasonable_length() {
        for (name, value) in all_domain_constants() {
            assert!(
                value.len() >= 11,
                "domain constant {name} is too short ({} bytes, min 11): {:?}",
                value.len(),
                core::str::from_utf8(value).unwrap_or("<invalid>")
            );
            assert!(
                value.len() <= 64,
                "domain constant {name} is too long ({} bytes, max 64): {:?}",
                value.len(),
                core::str::from_utf8(value).unwrap_or("<invalid>")
            );
        }
    }

    #[test]
    fn no_duplicate_values() {
        let all = all_domain_constants();
        let mut seen = HashSet::new();
        for (name, value) in &all {
            assert!(
                seen.insert(*value),
                "duplicate domain constant value for {name}: {value:?}"
            );
        }
    }

    #[test]
    fn no_duplicate_names() {
        let all = all_domain_constants();
        let mut seen = HashSet::new();
        for (name, _) in &all {
            assert!(seen.insert(*name), "duplicate domain constant name: {name}");
        }
    }

    #[test]
    fn fixture_covers_all_module_constants() {
        // Verify the fixture count matches the number of `pub const` items
        // defined in this module. If you add a constant and forget to add it
        // to `all_domain_constants()`, this test will catch it.
        //
        // Update this count when adding new constants.
        let expected_count = 13;
        let actual = all_domain_constants();
        assert_eq!(
            actual.len(),
            expected_count,
            "all_domain_constants() has {} entries but expected {expected_count}. \
             Did you add a new constant without updating the fixture?",
            actual.len()
        );
    }
}
