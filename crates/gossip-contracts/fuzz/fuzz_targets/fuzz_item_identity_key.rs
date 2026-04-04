//! Fuzzes the identity-key constructors that normalize connector, instance, and
//! object-version bytes into stable identifiers.
//!
//! The harness intentionally exercises constructor boundaries without turning
//! documented precondition panics into fuzz failures. Length checks ensure each
//! slice matches the field widths expected by `ItemIdentityKey::new`, and the
//! ASCII-tag path is wrapped in `catch_unwind` because invalid human-readable
//! tags are part of the input space being explored.
#![no_main]

use libfuzzer_sys::fuzz_target;

use gossip_contracts::identity::{
    ConnectorInstanceIdHash, ConnectorTag, ItemIdentityKey, ObjectVersionId,
};

fuzz_target!(|data: &[u8]| {
    // Empty and too-long tags are filtered out here. Non-graphic bytes are
    // still intentionally exercised inside `catch_unwind` so the fuzzer can
    // probe the documented ASCII-validation panic path without reporting it as
    // a harness crash.
    if !data.is_empty() && data.len() <= 8 {
        let _ = std::panic::catch_unwind(|| ConnectorTag::from_ascii(data));
    }

    if data.len() >= 41 {
        // The constructor expects 8 tag bytes, 32 instance-id bytes, and a
        // non-empty locator suffix.
        let tag_bytes: [u8; 8] = data[..8].try_into().unwrap();
        let instance_id_bytes = &data[8..40];
        let locator = data[40..].to_vec();
        if !locator.is_empty() {
            let connector = ConnectorTag::from_bytes(tag_bytes);
            let key = ItemIdentityKey::new(
                connector,
                ConnectorInstanceIdHash::from_instance_id_bytes(instance_id_bytes),
                locator,
            );
            // Stable-ID derivation should remain panic-free for any accepted key.
            let _ = key.stable_id();
        }
    }

    // Version IDs accept arbitrary non-empty byte sequences.
    if !data.is_empty() {
        let _ = ObjectVersionId::from_version_bytes(data);
    }
});
