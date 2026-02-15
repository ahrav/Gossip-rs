use gossip_contracts::identity::{
    CURRENT_EVIDENCE_VERSION, CURRENT_VERSION, IdHashMode, PolicyHash, PolicyHashInputs, TenantId,
    compute_policy_hash,
};

// --- Size + ZERO sentinel checks -------------------------------------------
gossip_contracts::smoke_test_id_32!(TenantId, PolicyHash);

#[test]
fn policy_hash_computes_non_zero() {
    let inputs = PolicyHashInputs {
        policy_hash_version: CURRENT_VERSION,
        id_hash_mode: IdHashMode::KeyedV1,
        evidence_hash_version: CURRENT_EVIDENCE_VERSION,
        rules_digest: [0xAA; 32],
    };
    let hash = compute_policy_hash(&inputs);
    assert_ne!(hash, PolicyHash::ZERO);
}

#[test]
fn id_hash_mode_roundtrip() {
    assert_eq!(IdHashMode::from_u8(0), Some(IdHashMode::Unkeyed));
    assert_eq!(IdHashMode::from_u8(1), Some(IdHashMode::KeyedV1));
    assert_eq!(IdHashMode::Unkeyed.as_u8(), 0);
    assert_eq!(IdHashMode::KeyedV1.as_u8(), 1);
}

#[test]
fn version_constants_are_positive() {
    const { assert!(CURRENT_VERSION > 0) };
    const { assert!(CURRENT_EVIDENCE_VERSION > 0) };
}
