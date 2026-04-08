//! End-to-end fuzzing harness for the identity derivation pipeline.
//!
//! Validates the deterministic nature of the identity derivation chain,
//! encompassing tenant secret generation, item identity, finding identity,
//! and occurrence identity. By processing these steps sequentially from a
//! single fuzz input, the entire pipeline is evaluated collectively.
//!
//! The harness interprets the first 160 bytes of every fuzz input as the fixed
//! pieces of the derivation (tenant secret key hash, norm digest, tenant id,
//! rule fingerprint, and connector instance identifier) while any additional
//! bytes seed the item path so that the item identity is influenced by both
//! deterministic and variable-width inputs.
//!
//! # Input Layout
//!
//! - **Bytes 0..32:** Tenant secret key governing `TenantSecretKey`.
//! - **Bytes 32..64:** Norm digest mixed with tenant key to produce the
//!   shared key secret hash.
//! - **Bytes 64..96:** Tenant identifier used downstream by `FindingIdInputs`.
//! - **Bytes 96..128:** Rule fingerprint that qualifies the finding derivation.
//! - **Bytes 128..160:** Connector instance identifier that anchors the item
//!   identity.
//! - **Bytes 160..n:** Optional item path payload that ensures the same
//!   fixed-width data can produce different stable item identifiers when the
//!   variable suffix changes; defaults to `b"\x42"` when absent.
//!
//! # Invariants
//!
//! - **Determinism:** Identical inputs to the derivation functions
//!   (`derive_finding_id`, `derive_occurrence_id`) produce identical output
//!   identifiers.

#![no_main]
use libfuzzer_sys::fuzz_target;

use gossip_contracts::identity::{
    ConnectorInstanceIdHash, ConnectorTag, FindingIdInputs, ItemIdentityKey, NormHash,
    ObjectVersionId, OccurrenceIdInputs, RuleFingerprint, TenantId, TenantSecretKey,
    derive_finding_id, derive_occurrence_id, key_secret_hash,
};

fuzz_target!(|data: &[u8]| {
    // Requires 160 bytes for the fixed-width portions of the derivation chain.
    if data.len() < 160 {
        return;
    }

    let tenant_key_bytes: [u8; 32] = data[0..32].try_into().unwrap();
    let norm_bytes: [u8; 32] = data[32..64].try_into().unwrap();
    let tenant_bytes: [u8; 32] = data[64..96].try_into().unwrap();
    let rule_bytes: [u8; 32] = data[96..128].try_into().unwrap();
    let instance_id_bytes = &data[128..160];

    // Variable-width path stretches the same fixed hashes into multiple stable
    // item identities by mutating the item payload that downstream inputs
    // consume.
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

    // Validates that deriving a `FindingId` twice from the same inputs remains
    // deterministic even after fuzz inputs mutate the upstream components.
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

    // Ensures that the occurrence derivation between the same finding, version,
    // and byte range is also stable in the face of fuzz mutations.
    let occ_1 = derive_occurrence_id(&occ_inputs);
    let occ_2 = derive_occurrence_id(&occ_inputs);
    assert_eq!(occ_1, occ_2, "OccurrenceId derivation is not deterministic");
});
