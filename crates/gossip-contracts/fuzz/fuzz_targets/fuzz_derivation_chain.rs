#![no_main]
use libfuzzer_sys::fuzz_target;

use gossip_contracts::identity::{
    derive_finding_id, derive_occurrence_id, key_secret_hash, ConnectorTag, FindingIdInputs,
    ItemIdentityKey, NormHash, ObjectVersionId, OccurrenceIdInputs, RuleFingerprint, TenantId,
    TenantSecretKey,
};

fuzz_target!(|data: &[u8]| {
    // Need at least 128 bytes to fill the full derivation chain inputs.
    if data.len() < 128 {
        return;
    }

    // Slice the input into fields.
    let tenant_key_bytes: [u8; 32] = data[0..32].try_into().unwrap();
    let norm_bytes: [u8; 32] = data[32..64].try_into().unwrap();
    let tenant_bytes: [u8; 32] = data[64..96].try_into().unwrap();
    let rule_bytes: [u8; 32] = data[96..128].try_into().unwrap();

    // Use remaining bytes as item path (or a fallback).
    let path = if data.len() > 128 {
        data[128..].to_vec()
    } else {
        vec![0x42]
    };

    let connector = ConnectorTag::from_bytes(*b"fuzztest");
    let item_key = ItemIdentityKey::new(connector, path);
    let stable_id = item_key.stable_id();

    let tenant_key = TenantSecretKey::from_bytes(tenant_key_bytes);
    let norm = NormHash::from_digest(norm_bytes);
    let secret = key_secret_hash(&tenant_key, &norm);

    let finding_inputs = FindingIdInputs {
        tenant: TenantId::from_bytes(tenant_bytes),
        item: stable_id,
        rule: RuleFingerprint::from_bytes(rule_bytes),
        secret,
    };

    // Derive twice and assert determinism.
    let finding_1 = derive_finding_id(&finding_inputs);
    let finding_2 = derive_finding_id(&finding_inputs);
    assert_eq!(
        finding_1, finding_2,
        "FindingId derivation is not deterministic"
    );

    let version = ObjectVersionId::from_version_bytes(b"fuzz-version");
    let occ_inputs = OccurrenceIdInputs {
        finding: finding_1,
        version,
        byte_offset: 0,
        byte_length: 1,
    };

    let occ_1 = derive_occurrence_id(&occ_inputs);
    let occ_2 = derive_occurrence_id(&occ_inputs);
    assert_eq!(occ_1, occ_2, "OccurrenceId derivation is not deterministic");
});
