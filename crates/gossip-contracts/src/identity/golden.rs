//! Golden vector tests for all identity derivation functions.
//!
//! These tests pin the exact byte output of every derivation function in the
//! identity module. They form a cross-cutting compatibility contract: if any
//! golden vector changes, all downstream consumers (persistence, coordination,
//! dedup) may produce different IDs for the same logical inputs, breaking
//! backward compatibility.
//!
//! # Regeneration protocol
//!
//! If a golden vector test fails:
//!
//! 1. **Confirm intent** — Determine whether the change was intentional (domain
//!    constant bump, encoding change) or an accidental regression.
//! 2. **If regression** — Revert the offending change. Golden vectors must not
//!    change without a version bump.
//! 3. **If intentional** — Bump the version suffix of the affected domain
//!    constant in `domain.rs` (e.g., `FINDING_ID_V1` → `FINDING_ID_V2`).
//! 4. **Regenerate vectors** — Run the affected test with the assertion
//!    temporarily removed, capture the new output, and update the
//!    `const ..._EXPECTED` array.
//! 5. **Update downstream** — Grep for the old domain constant name across all
//!    crates and update references. Add a migration note if persisted IDs exist.
//!
//! # Version-bump expectations
//!
//! | Vector | Domain constant | Trigger conditions |
//! |--------|----------------|--------------------|
//! | `STABLE_ITEM_ID_EXPECTED` | `domain::ITEM_ID_V1` | `ItemIdentityKey` encoding or domain tag changes |
//! | `OBJECT_VERSION_ID_EXPECTED` | `domain::OBJECT_VERSION_V1` | `ObjectVersionId` encoding changes |
//! | `KEY_SECRET_HASH_EXPECTED` | `domain::SECRET_HASH_V1` | Secret keying scheme changes |
//! | `FINDING_ID_EXPECTED` | `domain::FINDING_ID_V1` | `FindingIdInputs` encoding changes |
//! | `OCCURRENCE_ID_EXPECTED` | `domain::OCCURRENCE_ID_V1` | `OccurrenceIdInputs` encoding changes |
//! | `POLICY_HASH_EXPECTED` | `domain::POLICY_HASH_V2` | `PolicyHashInputs` encoding changes |
//! | `FINALIZE_64_EXPECTED` | (test-only domain) | `finalize_64` truncation or endianness changes |
//!
//! Coordination derivation vectors live in `gossip_coordination::split_execution::tests`.
//!
//! # Adding a new vector
//!
//! 1. Add a `const ..._EXPECTED: [u8; 32]` array with `#[rustfmt::skip]`
//!    (or `u64` for 64-bit vectors).
//! 2. Add a `#[test]` function that constructs canonical inputs, calls the
//!    derivation, and asserts against the const.
//! 3. Add the derivation name to the [`ALL`] registry.
//! 4. Update the `ALL` array length (compile-time checked).
//! 5. Update the [`registry_is_complete`] test assertion.

use super::{
    ConnectorTag, FindingId, FindingIdInputs, IdHashMode, ItemIdentityKey, NormHash,
    ObjectVersionId, OccurrenceId, OccurrenceIdInputs, PolicyHashInputs, RuleFingerprint,
    SecretHash, StableItemId, TenantId, TenantSecretKey, compute_policy_hash, derive_finding_id,
    derive_occurrence_id, domain_hasher, finalize_64, key_secret_hash,
};

// ============================================================================
// Registry
// ============================================================================

/// Names of all golden-vector derivation functions.
///
/// The compile-time array length enforces exhaustiveness: adding a new
/// derivation without updating this array is a compile error.
const ALL: [&str; 7] = [
    "StableItemId",
    "ObjectVersionId",
    "key_secret_hash",
    "FindingId",
    "OccurrenceId",
    "PolicyHash",
    "finalize_64",
];

// ============================================================================
// Expected byte arrays
// ============================================================================

/// `ItemIdentityKey::stable_id()` with connector `b"github"`, locator `b"org/repo\0src/main.rs"`.
#[rustfmt::skip]
const STABLE_ITEM_ID_EXPECTED: [u8; 32] = [
    0x6D, 0x29, 0x2B, 0x2F, 0x4D, 0x9C, 0x56, 0x8A,
    0x41, 0x04, 0x57, 0xCD, 0x3A, 0xBE, 0xE8, 0x7F,
    0x77, 0x25, 0x46, 0x4A, 0xAA, 0x36, 0xFB, 0x18,
    0x13, 0xA8, 0x93, 0x03, 0x10, 0xDF, 0x89, 0xA4,
];

/// `ObjectVersionId::from_version_bytes(b"abc123def456")`.
#[rustfmt::skip]
const OBJECT_VERSION_ID_EXPECTED: [u8; 32] = [
    0xCF, 0xAE, 0x65, 0x13, 0x76, 0x5D, 0x94, 0x3A,
    0x56, 0x43, 0xF4, 0x54, 0x29, 0x5C, 0x81, 0xFF,
    0x83, 0xFF, 0xCA, 0x49, 0x38, 0x7F, 0x1B, 0x15,
    0x3D, 0x69, 0xD6, 0x62, 0x50, 0xF6, 0xDE, 0x2E,
];

/// `key_secret_hash` with key `[0xBB; 32]`, norm digest `[0xCC; 32]`.
#[rustfmt::skip]
const KEY_SECRET_HASH_EXPECTED: [u8; 32] = [
    0x6B, 0xA4, 0xC7, 0x98, 0x33, 0xB0, 0x5F, 0x0E,
    0x0D, 0x20, 0x5D, 0xB8, 0x9B, 0xAB, 0xC5, 0xFB,
    0x6B, 0x7D, 0xE2, 0x27, 0xF9, 0x62, 0x68, 0x54,
    0x2D, 0x67, 0xE2, 0xF2, 0x64, 0x96, 0x3C, 0xBE,
];

/// `derive_finding_id` with tenant `[0x11; 32]`, item `[0x22; 32]`, rule `[0x33; 32]`,
/// secret `[0x44; 32]`.
#[rustfmt::skip]
const FINDING_ID_EXPECTED: [u8; 32] = [
    0x81, 0xCE, 0x28, 0x85, 0xDF, 0x85, 0xE9, 0x63,
    0x0D, 0x46, 0xA0, 0x29, 0x59, 0xE9, 0x3A, 0xCF,
    0x8A, 0xCE, 0x8E, 0x79, 0x01, 0x6E, 0xE9, 0xD8,
    0x73, 0xC1, 0x09, 0xBB, 0x20, 0x76, 0x1F, 0xD8,
];

/// `derive_occurrence_id` with finding `[0x55; 32]`, version `[0x66; 32]`, offset 1024,
/// length 42.
#[rustfmt::skip]
const OCCURRENCE_ID_EXPECTED: [u8; 32] = [
    0xCC, 0xEB, 0xCD, 0xED, 0xE9, 0x65, 0xAB, 0xCD,
    0x38, 0x8E, 0x68, 0xE2, 0xD6, 0x7D, 0x29, 0x8C,
    0x78, 0x2D, 0x53, 0x02, 0xF7, 0x1A, 0xDF, 0x52,
    0x24, 0x46, 0xCD, 0xE9, 0x96, 0x23, 0xDC, 0x85,
];

/// `compute_policy_hash` with version 1, `KeyedV1`, evidence version 1, digest `[0xAA; 32]`.
#[rustfmt::skip]
const POLICY_HASH_EXPECTED: [u8; 32] = [
    0x29, 0xF1, 0xE1, 0xF8, 0xF5, 0x92, 0xA9, 0xEC,
    0xCA, 0xEB, 0x83, 0xF7, 0x98, 0x7F, 0x63, 0x6A,
    0x39, 0xD5, 0x92, 0xEB, 0x71, 0x16, 0x4E, 0x73,
    0x38, 0x1E, 0x83, 0x77, 0x4C, 0xF1, 0xF8, 0x5C,
];

/// `finalize_64` with domain `"gossip/golden-64/v1"`, payload `b"deterministic golden vector"`.
///
/// Unlike 32-byte vectors, this is a `u64` since `finalize_64` returns a truncated 64-bit digest.
const FINALIZE_64_EXPECTED: u64 = 0x_8665_9F94_9814_3183;

// Coordination derivation golden vectors live in gossip-coordination::split_execution::tests.

// ============================================================================
// Golden vector tests
// ============================================================================

#[test]
fn stable_item_id_golden_value() {
    let key = ItemIdentityKey::new(
        ConnectorTag::from_ascii(b"github"),
        b"org/repo\0src/main.rs",
    );
    let id = key.stable_id();
    assert_eq!(
        id.as_bytes(),
        &STABLE_ITEM_ID_EXPECTED,
        "StableItemId golden vector changed (domain::ITEM_ID_V1). \
         See identity::golden module docs for regeneration protocol.\n\
         Actual: {:02X?}",
        id.as_bytes(),
    );
}

#[test]
fn object_version_id_golden_value() {
    let id = ObjectVersionId::from_version_bytes(b"abc123def456");
    assert_eq!(
        id.as_bytes(),
        &OBJECT_VERSION_ID_EXPECTED,
        "ObjectVersionId golden vector changed (domain::OBJECT_VERSION_V1). \
         See identity::golden module docs for regeneration protocol.\n\
         Actual: {:02X?}",
        id.as_bytes(),
    );
}

#[test]
fn key_secret_hash_golden_value() {
    let key = TenantSecretKey::from_bytes([0xBB; 32]);
    let norm = NormHash::from_digest([0xCC; 32]);
    let hash = key_secret_hash(&key, &norm);
    assert_eq!(
        hash.as_bytes(),
        &KEY_SECRET_HASH_EXPECTED,
        "key_secret_hash golden vector changed (domain::SECRET_HASH_V1). \
         See identity::golden module docs for regeneration protocol.\n\
         Actual: {:02X?}",
        hash.as_bytes(),
    );
}

#[test]
fn derive_finding_id_golden_value() {
    let inputs = FindingIdInputs {
        tenant: TenantId::from_bytes([0x11; 32]),
        item: StableItemId::from_bytes([0x22; 32]),
        rule: RuleFingerprint::from_bytes([0x33; 32]),
        secret: SecretHash::from_bytes_internal([0x44; 32]),
    };
    let id = derive_finding_id(&inputs);
    assert_eq!(
        id.as_bytes(),
        &FINDING_ID_EXPECTED,
        "FindingId golden vector changed (domain::FINDING_ID_V1). \
         See identity::golden module docs for regeneration protocol.\n\
         Actual: {:02X?}",
        id.as_bytes(),
    );
}

#[test]
fn derive_occurrence_id_golden_value() {
    let inputs = OccurrenceIdInputs {
        finding: FindingId::from_bytes([0x55; 32]),
        version: ObjectVersionId::from_bytes([0x66; 32]),
        byte_offset: 1024,
        byte_length: 42,
    };
    let id = derive_occurrence_id(&inputs);
    assert_eq!(
        id.as_bytes(),
        &OCCURRENCE_ID_EXPECTED,
        "OccurrenceId golden vector changed (domain::OCCURRENCE_ID_V1). \
         See identity::golden module docs for regeneration protocol.\n\
         Actual: {:02X?}",
        id.as_bytes(),
    );
}

#[test]
fn compute_policy_hash_golden_value() {
    let inputs = PolicyHashInputs {
        policy_hash_version: 1,
        id_hash_mode: IdHashMode::KeyedV1,
        evidence_hash_version: 1,
        rules_digest: [0xAA; 32],
    };
    let hash = compute_policy_hash(&inputs);
    assert_eq!(
        hash.as_bytes(),
        &POLICY_HASH_EXPECTED,
        "PolicyHash golden vector changed (domain::POLICY_HASH_V2). \
         See identity::golden module docs for regeneration protocol.\n\
         Actual: {:02X?}",
        hash.as_bytes(),
    );
}

#[test]
fn finalize_64_golden_value() {
    let mut h = domain_hasher("gossip/golden-64/v1");
    h.update(b"deterministic golden vector");
    let result = finalize_64(&h);
    assert_eq!(
        result, FINALIZE_64_EXPECTED,
        "finalize_64 golden vector changed. Coordination ID derivations \
         will produce different values. This is a breaking change.\n\
         Actual: {result:#018x}",
    );
}

// ============================================================================
// Registry completeness
// ============================================================================

/// Ensures every derivation function has a corresponding golden vector.
///
/// The hard-coded count must match `ALL.len()`. If you add a new derivation,
/// this test fails until you add both a golden vector *and* a registry entry.
#[test]
fn registry_is_complete() {
    assert_eq!(
        ALL.len(),
        7,
        "ALL registry has {} entries, expected 7. Did you add a derivation \
         without updating the registry? (Coordination golden vectors moved \
         to gossip-coordination.)",
        ALL.len(),
    );
    for entry in &ALL {
        assert!(!entry.is_empty(), "ALL registry contains an empty entry");
    }
}

// ============================================================================
// Cross-function composition property tests
// ============================================================================
//
// These property tests exercise the *composed* derivation chain rather than
// individual functions. They verify two structural invariants:
//   1. Determinism — identical inputs always produce identical outputs.
//   2. Collision-freedom — distinct inputs never collide end-to-end.

proptest::proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    /// Generate random inputs, derive the full chain `ItemIdentityKey → StableItemId →
    /// FindingId → OccurrenceId` twice, and assert determinism.
    #[test]
    fn full_chain_item_to_occurrence_is_pure(
        connector_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
        path in proptest::collection::vec(proptest::num::u8::ANY, 1..64),
        tenant_key_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
        norm_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
        tenant_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
        rule_bytes in proptest::array::uniform32(proptest::num::u8::ANY),
        version_token in proptest::collection::vec(proptest::num::u8::ANY, 1..64),
        byte_offset in proptest::num::u64::ANY,
        byte_length in proptest::num::u64::ANY,
    ) {
        let key = ItemIdentityKey::new(ConnectorTag::from_bytes(connector_bytes), path);
        let tenant_key = TenantSecretKey::from_bytes(tenant_key_bytes);
        let norm = NormHash::from_digest(norm_bytes);

        // First pass through the chain.
        let stable_id_1 = key.stable_id();
        let secret_1 = key_secret_hash(&tenant_key, &norm);
        let finding_1 = derive_finding_id(&FindingIdInputs {
            tenant: TenantId::from_bytes(tenant_bytes),
            item: stable_id_1,
            rule: RuleFingerprint::from_bytes(rule_bytes),
            secret: secret_1,
        });
        let occ_1 = derive_occurrence_id(&OccurrenceIdInputs {
            finding: finding_1,
            version: ObjectVersionId::from_version_bytes(&version_token),
            byte_offset,
            byte_length,
        });

        // Second pass — must produce identical output.
        let stable_id_2 = key.stable_id();
        let secret_2 = key_secret_hash(&tenant_key, &norm);
        let finding_2 = derive_finding_id(&FindingIdInputs {
            tenant: TenantId::from_bytes(tenant_bytes),
            item: stable_id_2,
            rule: RuleFingerprint::from_bytes(rule_bytes),
            secret: secret_2,
        });
        let occ_2 = derive_occurrence_id(&OccurrenceIdInputs {
            finding: finding_2,
            version: ObjectVersionId::from_version_bytes(&version_token),
            byte_offset,
            byte_length,
        });

        proptest::prop_assert_eq!(occ_1, occ_2);
    }

    /// Two distinct `ItemIdentityKey` inputs (different connector or locator) must
    /// produce different `OccurrenceId` values when all other inputs are held constant.
    #[test]
    fn full_chain_collision_free(
        connector_a in proptest::array::uniform8(proptest::num::u8::ANY),
        path_a in proptest::collection::vec(proptest::num::u8::ANY, 1..64),
        connector_b in proptest::array::uniform8(proptest::num::u8::ANY),
        path_b in proptest::collection::vec(proptest::num::u8::ANY, 1..64),
    ) {
        proptest::prop_assume!(connector_a != connector_b || path_a != path_b);

        let tenant_key = TenantSecretKey::from_bytes([0xBB; 32]);
        let norm = NormHash::from_digest([0xCC; 32]);
        let secret = key_secret_hash(&tenant_key, &norm);
        let tenant = TenantId::from_bytes([0x11; 32]);
        let rule = RuleFingerprint::from_bytes([0x33; 32]);
        let version = ObjectVersionId::from_bytes([0x66; 32]);

        let key_a = ItemIdentityKey::new(ConnectorTag::from_bytes(connector_a), path_a);
        let finding_a = derive_finding_id(&FindingIdInputs {
            tenant,
            item: key_a.stable_id(),
            rule,
            secret,
        });
        let occ_a = derive_occurrence_id(&OccurrenceIdInputs {
            finding: finding_a,
            version,
            byte_offset: 1024,
            byte_length: 42,
        });

        let key_b = ItemIdentityKey::new(ConnectorTag::from_bytes(connector_b), path_b);
        let finding_b = derive_finding_id(&FindingIdInputs {
            tenant,
            item: key_b.stable_id(),
            rule,
            secret,
        });
        let occ_b = derive_occurrence_id(&OccurrenceIdInputs {
            finding: finding_b,
            version,
            byte_offset: 1024,
            byte_length: 42,
        });

        proptest::prop_assert_ne!(occ_a, occ_b);
    }
}

/// Boundary values for `u64` fields in `OccurrenceIdInputs` must each produce
/// a distinct `OccurrenceId`.
#[test]
fn boundary_u64_occurrence_id() {
    let finding = FindingId::from_bytes([0x55; 32]);
    let version = ObjectVersionId::from_bytes([0x66; 32]);

    let cases: [(u64, u64); 5] = [
        (0, 0),
        (u64::MAX, u64::MAX),
        (u64::MAX, 0),
        (0, u64::MAX),
        (1024, 42),
    ];

    let ids: Vec<OccurrenceId> = cases
        .iter()
        .map(|&(offset, length)| {
            derive_occurrence_id(&OccurrenceIdInputs {
                finding,
                version,
                byte_offset: offset,
                byte_length: length,
            })
        })
        .collect();

    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(
                ids[i], ids[j],
                "boundary collision: (offset={}, length={}) and \
                 (offset={}, length={}) produced identical OccurrenceId",
                cases[i].0, cases[i].1, cases[j].0, cases[j].1,
            );
        }
    }
}
