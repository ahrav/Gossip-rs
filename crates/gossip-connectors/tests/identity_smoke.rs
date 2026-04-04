//! Smoke tests for connector identity primitives used by connector-facing APIs.
//!
//! These checks protect a few cross-cutting invariants that other crates rely on:
//! fixed-width identifier wrappers retain their size and zero sentinel semantics,
//! ASCII connector tags are zero-padded deterministically, stable item ids derived
//! from connector identity material never collapse to zero, and distinct version
//! bytes hash to distinct non-zero object version ids.

use gossip_contracts::identity::{
    ConnectorInstanceIdHash, ConnectorTag, ItemIdentityKey, ObjectVersionId, StableItemId,
};

gossip_contracts::smoke_test_id_32!(ConnectorInstanceIdHash, StableItemId, ObjectVersionId);
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
fn item_identity_key_derives_non_zero_stable_id() {
    let tag = ConnectorTag::from_ascii(b"github");
    let instance = ConnectorInstanceIdHash::from_instance_id_bytes(b"github-installation-1");
    // The locator keeps connector-local structure by separating path segments with NUL.
    let key = ItemIdentityKey::new(tag, instance, b"org/repo\0src/main.rs");

    let id = key.stable_id();
    assert_ne!(id, StableItemId::ZERO);
    assert_eq!(key.connector(), tag);
    assert_eq!(key.connector_instance(), instance);
    assert_eq!(key.locator(), b"org/repo\0src/main.rs");
}

#[test]
fn object_version_id_from_version_bytes() {
    let v1 = ObjectVersionId::from_version_bytes(b"commit-aaa");
    let v2 = ObjectVersionId::from_version_bytes(b"commit-bbb");
    assert_ne!(v1, v2);
    assert_ne!(v1, ObjectVersionId::ZERO);
}
