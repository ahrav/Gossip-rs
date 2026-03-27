use super::{
    FILESYSTEM_CONNECTOR_TAG, GIT_CONNECTOR_TAG, ItemKey, derive_filesystem_stable_item_id,
    derive_stable_item_id,
};
use crate::identity::{ConnectorInstanceIdHash, ItemIdentityKey};

#[test]
fn derive_stable_item_id_changes_when_connector_instance_changes() {
    let item_key = ItemKey::try_from_slice(b"src/main.rs").expect("item key");
    let instance_a = ConnectorInstanceIdHash::from_instance_id_bytes(b"/repo-a");
    let instance_b = ConnectorInstanceIdHash::from_instance_id_bytes(b"/repo-b");

    let stable_a = derive_filesystem_stable_item_id(instance_a, &item_key);
    let stable_b = derive_filesystem_stable_item_id(instance_b, &item_key);

    assert_ne!(stable_a, stable_b);
}

#[test]
fn derive_stable_item_id_is_stable_for_same_inputs() {
    let item_key = ItemKey::try_from_slice(b"src/main.rs").expect("item key");
    let instance = ConnectorInstanceIdHash::from_instance_id_bytes(b"/repo-a");

    let stable_a = derive_filesystem_stable_item_id(instance, &item_key);
    let stable_b = derive_filesystem_stable_item_id(instance, &item_key);

    assert_eq!(stable_a, stable_b);
}

#[test]
fn derive_filesystem_stable_item_id_matches_manual_item_identity_key_derivation() {
    let item_key = ItemKey::try_from_slice(b"nested/file.txt").expect("item key");
    let instance = ConnectorInstanceIdHash::from_instance_id_bytes(b"/var/data/project");

    let derived = derive_filesystem_stable_item_id(instance, &item_key);
    let manual = ItemIdentityKey::new(FILESYSTEM_CONNECTOR_TAG, instance, item_key.as_bytes())
        .stable_id();

    assert_eq!(derived, manual);
}

#[test]
fn derive_stable_item_id_changes_when_connector_tag_changes() {
    let item_key = ItemKey::try_from_slice(b"same/path.txt").expect("item key");
    let instance = ConnectorInstanceIdHash::from_instance_id_bytes(b"instance-1");

    let filesystem_id = derive_stable_item_id(FILESYSTEM_CONNECTOR_TAG, instance, &item_key);
    let git_id = derive_stable_item_id(GIT_CONNECTOR_TAG, instance, &item_key);

    assert_ne!(filesystem_id, git_id);
}
