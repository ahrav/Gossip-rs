#![no_main]
use libfuzzer_sys::fuzz_target;

use gossip_contracts::identity::{
    ConnectorInstanceIdHash, ConnectorTag, ItemIdentityKey, ObjectVersionId,
};

fuzz_target!(|data: &[u8]| {
    // Fuzz ConnectorTag::from_ascii — must not panic on arbitrary bytes
    // (except for documented panics on empty/too-long/non-graphic input).
    if !data.is_empty() && data.len() <= 8 {
        let _ = std::panic::catch_unwind(|| ConnectorTag::from_ascii(data));
    }

    // Fuzz ItemIdentityKey::new — must not panic except on empty locator.
    if data.len() >= 9 {
        let tag_bytes: [u8; 8] = data[..8].try_into().unwrap();
        let locator = data[8..].to_vec();
        if !locator.is_empty() {
            let connector = ConnectorTag::from_bytes(tag_bytes);
            let key = ItemIdentityKey::new(
                connector,
                ConnectorInstanceIdHash::from_instance_id_bytes(b"fuzz-instance"),
                locator,
            );
            // Derive stable_id — must not panic.
            let _ = key.stable_id();
        }
    }

    // Fuzz ObjectVersionId::from_version_bytes — must not panic on non-empty input.
    if !data.is_empty() {
        let _ = ObjectVersionId::from_version_bytes(data);
    }
});
