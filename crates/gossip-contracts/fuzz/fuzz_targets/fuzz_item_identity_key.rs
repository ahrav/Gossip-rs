//! Fuzz target covering the identity-key normalization path in
//! `gossip_contracts::identity`.
//!
//! Connector tags, instance identifiers, and locators are composed from raw bytes so the
//! constructors see both valid and intentionally invalid inputs. Tagged precondition
//! panics are wrapped in `catch_unwind` so the fuzzer can still explore those failure
//! paths without aborting the harness, while every constructor call that satisfies the
//! documented field widths must remain panic-free.
//!
//! When a complete slice of [tag, instance, locator] bytes is available we also derive the
//! corresponding `stable_id`, and all arbitrary version bytes are funneled through
//! `ObjectVersionId::from_version_bytes` to ensure the parsing work stays resilient under fuzzing.
#![no_main]

use libfuzzer_sys::fuzz_target;

use gossip_contracts::identity::{
    ConnectorInstanceIdHash, ConnectorTag, ItemIdentityKey, ObjectVersionId,
};

fuzz_target!(|data: &[u8]| {
    // Probe the documented ASCII-validation panic path for connector tags while keeping the
    // harness alive by wrapping the call in `catch_unwind`.
    if !data.is_empty() && data.len() <= 8 {
        let _ = std::panic::catch_unwind(|| ConnectorTag::from_ascii(data));
    }

    // Only when we have at least 41 bytes (8 tag, 32 instance, then a locator) can we build a
    // fully populated `ItemIdentityKey`.
    if data.len() >= 41 {
        let tag_bytes: [u8; 8] = data[..8].try_into().unwrap();
        let instance_id_bytes = &data[8..40];
        let locator = data[40..].to_vec();
        if !locator.is_empty() {
            // Only non-empty locators satisfy the published field bounds for stable IDs.
            let connector = ConnectorTag::from_bytes(tag_bytes);
            let key = ItemIdentityKey::new(
                connector,
                ConnectorInstanceIdHash::from_instance_id_bytes(instance_id_bytes),
                locator,
            );
            // Stable-ID derivation should remain panic-free for these fully populated inputs.
            let _ = key.stable_id();
        }
    }

    // Arbitrary version bytes should always parse into an `ObjectVersionId` without panicking.
    if !data.is_empty() {
        let _ = ObjectVersionId::from_version_bytes(data);
    }
});
