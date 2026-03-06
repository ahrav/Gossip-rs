use std::sync::LazyLock;

use blake3::Hasher;

use crate::{
    connector::VersionId,
    identity::{self, CanonicalBytes, StableItemId, hashing::derive_from_cached},
};

/// Cached derive-key hasher for [`OvidHash`] derivation.
static OVID_HASHER: LazyLock<Hasher> =
    LazyLock::new(|| Hasher::new_derive_key(identity::domain::OVID_V1));

crate::define_id_32! {
    /// Fixed-width hash of an object-version identity.
    ///
    /// `OvidHash` is the done-ledger join key for “these exact bytes under this
    /// stable item identity”. It is derived from:
    ///
    /// - [`StableItemId`] — already scoped by connector tag + connector instance
    /// - [`VersionId`] — including strong-vs-weak claim strength
    ///
    /// The same stable item under two different version claims therefore
    /// produces different `OvidHash` values.
    OvidHash
}

/// Structured inputs to [`derive_ovid_hash`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OvidHashInputs {
    stable_item_id: StableItemId,
    version: VersionId,
}

impl OvidHashInputs {
    /// Construct OVID-hash inputs from the stable item identity and version
    /// claim returned by a connector.
    #[inline]
    #[must_use]
    pub const fn new(stable_item_id: StableItemId, version: VersionId) -> Self {
        Self {
            stable_item_id,
            version,
        }
    }

    /// Stable item identity component.
    #[inline]
    #[must_use]
    pub const fn stable_item_id(self) -> StableItemId {
        self.stable_item_id
    }

    /// Version claim component.
    #[inline]
    #[must_use]
    pub const fn version(self) -> VersionId {
        self.version
    }
}

impl CanonicalBytes for OvidHashInputs {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.stable_item_id.write_canonical(h);
        write_version_id_canonical(self.version, h);
    }
}

/// Derive an [`OvidHash`] from stable item identity and version claim.
#[inline]
#[must_use]
pub fn derive_ovid_hash(inputs: &OvidHashInputs) -> OvidHash {
    OvidHash::from_bytes(derive_from_cached(&OVID_HASHER, inputs))
}

#[inline]
fn write_version_id_canonical(version: VersionId, h: &mut Hasher) {
    match version {
        VersionId::Strong(version_id) => {
            0u8.write_canonical(h);
            version_id.write_canonical(h);
        }
        VersionId::Weak(version_id) => {
            1u8.write_canonical(h);
            version_id.write_canonical(h);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        connector::VersionId,
        identity::{ObjectVersionId, StableItemId},
        test_util::{canonical_digest, miri_proptest_config},
    };

    use super::*;
    use proptest::prelude::*;

    fn stable_item(seed: u8) -> StableItemId {
        StableItemId::from_bytes([seed; 32])
    }

    fn version(seed: u8) -> ObjectVersionId {
        ObjectVersionId::from_bytes([seed; 32])
    }

    #[test]
    fn ovid_hash_is_deterministic_for_same_inputs() {
        let inputs = OvidHashInputs::new(stable_item(7), VersionId::Strong(version(11)));

        assert_eq!(derive_ovid_hash(&inputs), derive_ovid_hash(&inputs));
    }

    #[test]
    fn strong_and_weak_versions_hash_differ() {
        let stable_item_id = stable_item(3);
        let object_version_id = version(9);

        let strong = derive_ovid_hash(&OvidHashInputs::new(
            stable_item_id,
            VersionId::Strong(object_version_id),
        ));
        let weak = derive_ovid_hash(&OvidHashInputs::new(
            stable_item_id,
            VersionId::Weak(object_version_id),
        ));

        assert_ne!(strong, weak);
    }

    #[test]
    fn ovid_hash_inputs_canonical_digest_is_stable() {
        let inputs = OvidHashInputs::new(stable_item(21), VersionId::Weak(version(33)));

        assert_eq!(canonical_digest(&inputs), canonical_digest(&inputs));
    }

    proptest! {
        #![proptest_config(miri_proptest_config())]

        #[test]
        fn ovid_hash_is_deterministic_for_random_inputs(
            stable_item_bytes in any::<[u8; 32]>(),
            version_bytes in any::<[u8; 32]>(),
            is_strong in any::<bool>(),
        ) {
            let stable_item_id = StableItemId::from_bytes(stable_item_bytes);
            let object_version_id = ObjectVersionId::from_bytes(version_bytes);
            let version = if is_strong {
                VersionId::Strong(object_version_id)
            } else {
                VersionId::Weak(object_version_id)
            };
            let inputs = OvidHashInputs::new(stable_item_id, version);

            prop_assert_eq!(derive_ovid_hash(&inputs), derive_ovid_hash(&inputs));
        }
    }
}
