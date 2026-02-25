use gossip_contracts::identity::{ConnectorTag, ItemKey, ObjectVersionId, StableItemId};

// --- Size + ZERO sentinel checks -------------------------------------------
gossip_contracts::smoke_test_id_32!(StableItemId, ObjectVersionId);

// --- Size-only check (ConnectorTag is 8 bytes, not 32) ----------------------
gossip_contracts::smoke_test_id_size!(ConnectorTag, 8);

#[test]
fn connector_tag_from_ascii_works() {
    const GITHUB: ConnectorTag = ConnectorTag::from_ascii(b"github");
    const S3: ConnectorTag = ConnectorTag::from_ascii(b"s3");

    assert_eq!(GITHUB.as_bytes(), b"github\0\0");
    assert_eq!(S3.as_bytes(), b"s3\0\0\0\0\0\0");
    assert_ne!(GITHUB, S3);
}

#[test]
fn item_key_derives_non_zero_stable_id() {
    let tag = ConnectorTag::from_ascii(b"github");
    let key = ItemKey::new(tag, b"org/repo\0src/main.rs");

    let id = key.stable_id();
    assert_ne!(id, StableItemId::ZERO);
    assert_eq!(key.connector(), tag);
    assert_eq!(key.path(), b"org/repo\0src/main.rs");
}

#[test]
fn object_version_id_from_version_bytes() {
    let v1 = ObjectVersionId::from_version_bytes(b"commit-aaa");
    let v2 = ObjectVersionId::from_version_bytes(b"commit-bbb");
    assert_ne!(v1, v2);
    assert_ne!(v1, ObjectVersionId::ZERO);
}
