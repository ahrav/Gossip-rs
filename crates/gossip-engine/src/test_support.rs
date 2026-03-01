//! Shared test helpers for gossip-engine unit and integration tests.

use gossip_contracts::{
    connector::{ItemKey, ItemRef, ScanItem, VersionId},
    identity::{ObjectVersionId, StableItemId},
};

/// Build a [`ScanItem`] with a strong version from raw byte slices.
pub(crate) fn make_item(key: &[u8], item_ref: &[u8], stable: [u8; 32], version: &[u8]) -> ScanItem {
    ScanItem::new(
        ItemKey::try_from_slice(key).expect("valid key"),
        ItemRef::try_from_slice(item_ref).expect("valid ref"),
        StableItemId::from_bytes(stable),
        VersionId::Strong(ObjectVersionId::from_version_bytes(version)),
    )
}

/// Build a [`ScanItem`] with a weak version from raw byte slices.
pub(crate) fn make_weak_item(
    key: &[u8],
    item_ref: &[u8],
    stable: [u8; 32],
    version: &[u8],
) -> ScanItem {
    ScanItem::new(
        ItemKey::try_from_slice(key).expect("valid key"),
        ItemRef::try_from_slice(item_ref).expect("valid ref"),
        StableItemId::from_bytes(stable),
        VersionId::Weak(ObjectVersionId::from_version_bytes(version)),
    )
}
