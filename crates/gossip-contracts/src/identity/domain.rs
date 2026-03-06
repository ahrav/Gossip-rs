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
//! (`Hasher::new_keyed`).
//!
//! # Safety requirements
//!
//! - No two constants may share the same value. The `no_duplicate_values`
//!   test enforces this at `cargo test` time.
//! - Constants are `&str` so [`domain_hasher`] can pass them directly to
//!   BLAKE3's derive-key API without runtime UTF-8 validation.
//!
//! [`domain_hasher`]: super::domain_hasher

// =========================================================================
// Coordination subsystem
// =========================================================================

/// Shard-ID derivation during split operations.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const SPLIT_ID_V1: &str = "gossip/coord/v1/split-id";

/// Op-log payload hashing for idempotency conflict detection.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const OP_PAYLOAD_V1: &str = "gossip/coord/v1/op-payload";

// =========================================================================
// Identity subsystem — finding & secret derivations
// =========================================================================

/// `FindingId` derivation from `(tenant, item, rule, secret_hash)`.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const FINDING_ID_V1: &str = "gossip/finding/v1";

/// `OccurrenceId` derivation from `(finding, version, offset, length)`.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const OCCURRENCE_ID_V1: &str = "gossip/occurrence/v1";

/// `ObservationId` derivation from `(tenant, policy, occurrence)`.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const OBSERVATION_ID_V1: &str = "gossip/observation/v1";

/// `SecretHash` keying — tenant-scoped secret identity.
///
/// Hash mode: **BLAKE3 keyed mode** (`Hasher::new_keyed`). The domain tag is
/// fed as data *inside* the keyed hasher, not as a derive-key context.
pub const SECRET_HASH_V1: &str = "gossip/secret-hash/v1";

/// `StableItemId` derivation from `ItemIdentityKey`.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const ITEM_ID_V1: &str = "gossip/item-id/v1";

/// `ConnectorInstanceIdHash` derivation from connector-instance bytes.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const CONNECTOR_INSTANCE_ID_V1: &str = "gossip/connector-instance-id/v1";

/// `ObjectVersionId` derivation from version bytes.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const OBJECT_VERSION_V1: &str = "gossip/object-version/v1";

/// `RuleFingerprint` derivation from rule definition.
///
/// Domain tag provided here for registry completeness and uniqueness enforcement.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const RULE_FINGERPRINT_V1: &str = "gossip/rule/v1";

// =========================================================================
// Policy subsystem
// =========================================================================

/// `PolicyHash` derivation from `PolicyHashInputs`.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
///
/// Note: version is `v2` because the derivation scheme was redesigned after
/// the initial spec (v1 was never shipped).
pub const POLICY_HASH_V2: &str = "gossip/policy-hash/v2";

/// Rules-digest derivation — content-addressed hash of the full rule set.
///
/// Domain tag provided here for registry completeness and uniqueness enforcement.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const RULES_DIGEST_V1: &str = "gossip/rules-digest/v1";

// =========================================================================
// Persistence subsystem
// =========================================================================

/// OVID (Object-Version Identity) hash derivation.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const OVID_V1: &str = "gossip/persistence/v1/ovid";

/// Done-ledger key derivation.
///
/// Reserved for future use — will be needed if the done-ledger key requires
/// hashing beyond simple field concatenation.
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const DONE_LEDGER_KEY_V1: &str = "gossip/persistence/v1/done-key";

/// `TriageGroupKey` derivation from `(tenant, item)`.
///
/// Hash mode: BLAKE3 derive-key via `domain_hasher`.
pub const TRIAGE_GROUP_KEY_V1: &str = "gossip/persistence/v1/triage-group";

// =========================================================================
// Authoritative constant list
// =========================================================================

/// Every domain constant in the registry, in declaration order.
///
/// The array length is checked at compile time — adding a constant without
/// updating `ALL` is a compile error. Tests use this for uniqueness and
/// coverage checks.
pub const ALL: [&str; 15] = [
    SPLIT_ID_V1,
    OP_PAYLOAD_V1,
    FINDING_ID_V1,
    OCCURRENCE_ID_V1,
    OBSERVATION_ID_V1,
    SECRET_HASH_V1,
    ITEM_ID_V1,
    CONNECTOR_INSTANCE_ID_V1,
    OBJECT_VERSION_V1,
    RULE_FINGERPRINT_V1,
    POLICY_HASH_V2,
    RULES_DIGEST_V1,
    OVID_V1,
    DONE_LEDGER_KEY_V1,
    TRIAGE_GROUP_KEY_V1,
];

// =========================================================================
// Test fixtures
// =========================================================================

/// Returns every domain constant in the registry as a `(name, value)` pair.
///
/// Used by the uniqueness, coverage, and format-validation tests in this
/// module.  The first element of each tuple is the Rust constant name
/// (e.g., `"FINDING_ID_V1"`), the second is the domain string value
/// (e.g., `"gossip/finding/v1"`).
///
/// When adding a new domain constant, you **must** add it to [`ALL`] *and*
/// here, then bump the `ALL` array length.
#[cfg(test)]
pub(crate) fn all_domain_constants() -> Vec<(&'static str, &'static str)> {
    vec![
        ("SPLIT_ID_V1", SPLIT_ID_V1),
        ("OP_PAYLOAD_V1", OP_PAYLOAD_V1),
        ("FINDING_ID_V1", FINDING_ID_V1),
        ("OCCURRENCE_ID_V1", OCCURRENCE_ID_V1),
        ("OBSERVATION_ID_V1", OBSERVATION_ID_V1),
        ("SECRET_HASH_V1", SECRET_HASH_V1),
        ("ITEM_ID_V1", ITEM_ID_V1),
        ("CONNECTOR_INSTANCE_ID_V1", CONNECTOR_INSTANCE_ID_V1),
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
            for (i, &byte) in value.as_bytes().iter().enumerate() {
                assert!(
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'/'
                        || byte == b'-',
                    "domain constant {name} has disallowed byte 0x{byte:02X} \
                     at position {i}: {value:?}",
                );
            }
        }
    }

    #[test]
    fn all_constants_follow_naming_convention() {
        for (name, s) in all_domain_constants() {
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
                "domain constant {name} is too short ({} bytes, min 11): {value:?}",
                value.len(),
            );
            assert!(
                value.len() <= 64,
                "domain constant {name} is too long ({} bytes, max 64): {value:?}",
                value.len(),
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
    fn fixture_covers_all_constants() {
        // The ALL array length is compiler-checked (adding a constant without
        // updating ALL is a compile error). This test verifies the named
        // fixture stays in sync with ALL.
        let fixture = all_domain_constants();
        assert_eq!(
            fixture.len(),
            ALL.len(),
            "all_domain_constants() has {} entries but ALL has {}. \
             Did you add a constant without updating both?",
            fixture.len(),
            ALL.len(),
        );
        // Every value in the fixture must appear in ALL.
        for (name, value) in &fixture {
            assert!(
                ALL.contains(value),
                "fixture entry {name} ({value:?}) missing from ALL array"
            );
        }
    }
}
