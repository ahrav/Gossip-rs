//! Object-version identity hashing (OVID).
//!
//! This module provides the [`OvidHash`] type and derivation logic for creating
//! deterministic, stable hashes of object-version pairs. These hashes serve as
//! the primary join key in the done-ledger, associating exact bytes with a stable
//! item identity.
//!
//! The hashes ensure that weak and strong claims for the same stable item produce
//! distinct keys, avoiding cross-contamination of findings records.
//!
//! ## Canonical encoding invariants
//!
//! The hash preimage is encoded as:
//! 1. canonical bytes for [`StableItemId`]
//! 2. one-byte version-strength discriminator (`0` for strong, `1` for weak)
//! 3. canonical bytes for the underlying object version id
//!
//! This framing guarantees that a strong claim and weak claim for the same
//! version bytes cannot collide at the canonical-byte layer.

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
///
/// Fields are public to match peer input types ([`FindingIdInputs`],
/// [`OccurrenceIdInputs`], [`ObservationIdInputs`]).
///
/// [`FindingIdInputs`]: crate::identity::FindingIdInputs
/// [`OccurrenceIdInputs`]: crate::identity::OccurrenceIdInputs
/// [`ObservationIdInputs`]: crate::identity::ObservationIdInputs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OvidHashInputs {
    /// Stable item identity (connector-scoped).
    pub stable_item_id: StableItemId,
    /// Version claim (strong or weak) from the connector.
    pub version: VersionId,
}

impl CanonicalBytes for OvidHashInputs {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.stable_item_id.write_canonical(h);
        write_version_id_canonical(self.version, h);
    }
}

/// Derive an [`OvidHash`] from stable item identity and version claim.
///
/// This function is pure and deterministic for identical inputs. It performs no
/// allocation beyond hasher state and no I/O.
#[inline]
#[must_use]
pub fn derive_ovid_hash(inputs: &OvidHashInputs) -> OvidHash {
    OvidHash::from_bytes(derive_from_cached(&OVID_HASHER, inputs))
}

/// Encode [`VersionId`] canonically with an explicit strength discriminator.
///
/// The single-byte prefix is part of the hash domain:
/// - `0` => [`VersionId::Strong`]
/// - `1` => [`VersionId::Weak`]
///
/// This prevents canonical-byte ambiguity when the wrapped version id bytes are
/// identical across strengths.
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
        let inputs = OvidHashInputs {
            stable_item_id: stable_item(7),
            version: VersionId::Strong(version(11)),
        };

        assert_eq!(derive_ovid_hash(&inputs), derive_ovid_hash(&inputs));
    }

    #[test]
    fn strong_and_weak_versions_hash_differ() {
        let sid = stable_item(3);
        let object_version_id = version(9);

        let strong = derive_ovid_hash(&OvidHashInputs {
            stable_item_id: sid,
            version: VersionId::Strong(object_version_id),
        });
        let weak = derive_ovid_hash(&OvidHashInputs {
            stable_item_id: sid,
            version: VersionId::Weak(object_version_id),
        });

        assert_ne!(strong, weak);
    }

    #[test]
    fn ovid_hash_inputs_canonical_digest_is_stable() {
        let inputs = OvidHashInputs {
            stable_item_id: stable_item(21),
            version: VersionId::Weak(version(33)),
        };

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
            let ver = if is_strong {
                VersionId::Strong(object_version_id)
            } else {
                VersionId::Weak(object_version_id)
            };
            let inputs = OvidHashInputs { stable_item_id, version: ver };

            prop_assert_eq!(derive_ovid_hash(&inputs), derive_ovid_hash(&inputs));
        }
    }
}
