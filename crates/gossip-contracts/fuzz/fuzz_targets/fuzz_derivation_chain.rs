//! Fuzzes the identity derivation pipeline end to end.
//!
//! This harness feeds a single fuzz input through the tenant secret, item
//! identity, finding identity, and occurrence identity derivation steps so
//! libFuzzer can mutate the full chain as one corpus entry.
//!
//! The primary invariant is determinism: re-deriving a finding or occurrence
//! identifier from identical inputs must always yield the same value.

#![no_main]
use libfuzzer_sys::fuzz_target;

use gossip_contracts::identity::{
    ConnectorInstanceIdHash, ConnectorTag, FindingIdInputs, ItemIdentityKey, NormHash,
    ObjectVersionId, OccurrenceIdInputs, RuleFingerprint, TenantId, TenantSecretKey,
    derive_finding_id, derive_occurrence_id, key_secret_hash,
};

fuzz_target!(|data: &[u8]| {
    // The fixed-width portions of the derivation chain require 160 bytes.
    if data.len() < 160 {
        return;
    }

    let tenant_key_bytes: [u8; 32] = data[0..32].try_into().unwrap();
    let norm_bytes: [u8; 32] = data[32..64].try_into().unwrap();
    let tenant_bytes: [u8; 32] = data[64..96].try_into().unwrap();
    let rule_bytes: [u8; 32] = data[96..128].try_into().unwrap();
    let instance_id_bytes = &data[128..160];

    // Keep the path variable-width so one input can perturb both the fixed
    // hashes and the item identity payload that feeds later derivation steps.
    let path = if data.len() > 160 {
        data[160..].to_vec()
    } else {
        vec![0x42]
    };

    let connector = ConnectorTag::from_bytes(*b"fuzztest");
    let item_key = ItemIdentityKey::new(
        connector,
        ConnectorInstanceIdHash::from_instance_id_bytes(instance_id_bytes),
        path,
    );
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

    // Re-run the same derivation to prove the identifier remains stable.
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
