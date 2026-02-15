use gossip_contracts::identity::{
    FindingId, FindingIdInputs, NormHash, ObjectVersionId, OccurrenceId, OccurrenceIdInputs,
    RuleFingerprint, SecretHash, StableItemId, TenantId, TenantSecretKey, derive_finding_id,
    derive_occurrence_id, key_secret_hash,
};

// --- Size + ZERO sentinel checks (types with public ZERO constant) ----------
gossip_contracts::smoke_test_id_32!(RuleFingerprint, FindingId, OccurrenceId);

// --- Size-only checks (restricted types, no ZERO sentinel) ------------------
gossip_contracts::smoke_test_id_size!(NormHash, 32);
gossip_contracts::smoke_test_id_size!(SecretHash, 32);

#[test]
fn derivation_chain_produces_non_zero_output() {
    let tenant = TenantId::from_bytes([0x01; 32]);
    let key = TenantSecretKey::from_bytes([0x02; 32]);
    let norm = NormHash::from_digest([0x03; 32]);
    let rule = RuleFingerprint::from_bytes([0x04; 32]);
    let item = StableItemId::from_bytes([0x05; 32]);
    let version = ObjectVersionId::from_bytes([0x06; 32]);

    let secret = key_secret_hash(&key, &norm);
    assert_ne!(*secret.as_bytes(), [0u8; 32]);

    let finding = derive_finding_id(&FindingIdInputs {
        tenant,
        item,
        rule,
        secret,
    });
    assert_ne!(finding, FindingId::ZERO);

    let occurrence = derive_occurrence_id(&OccurrenceIdInputs {
        finding,
        version,
        byte_offset: 42,
        byte_length: 100,
    });
    assert_ne!(occurrence, OccurrenceId::ZERO);
}
