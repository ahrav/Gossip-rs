#![no_main]
use libfuzzer_sys::fuzz_target;

use gossip_contracts::identity::{ConnectorTag, ItemKey, ObjectVersionId};

fuzz_target!(|data: &[u8]| {
    // Fuzz ConnectorTag::from_ascii — must not panic on arbitrary bytes
    // (except for documented panics on empty/too-long/non-graphic input).
    if !data.is_empty() && data.len() <= 8 {
        let _ = std::panic::catch_unwind(|| ConnectorTag::from_ascii(data));
    }

    // Fuzz ItemKey::new — must not panic except on empty path.
    if data.len() >= 9 {
        let tag_bytes: [u8; 8] = data[..8].try_into().unwrap();
        let path = data[8..].to_vec();
        if !path.is_empty() {
            let connector = ConnectorTag::from_bytes(tag_bytes);
            let key = ItemKey::new(connector, path);
            // Derive stable_id — must not panic.
            let _ = key.stable_id();
        }
    }

    // Fuzz ObjectVersionId::from_version_bytes — must not panic on non-empty input.
    if !data.is_empty() {
        let _ = ObjectVersionId::from_version_bytes(data);
    }
});
