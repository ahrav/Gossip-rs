//! Conversion helpers between Git simulation types and Git scan types.

use crate::{ObjectFormat, OidBytes};

use super::error::SimGitError;
use super::scenario::{GitObjectFormat, GitOid};

/// Converts a simulation object format into the Git scan object format.
#[inline]
#[must_use]
pub const fn to_object_format(format: GitObjectFormat) -> ObjectFormat {
    match format {
        GitObjectFormat::Sha1 => ObjectFormat::Sha1,
        GitObjectFormat::Sha256 => ObjectFormat::Sha256,
    }
}

/// Convert a simulation OID into `OidBytes`, validating length.
///
/// Returns `SimGitError::InvalidOidLength` when the OID length does not match
/// the provided object format.
pub fn to_oid_bytes(oid: &GitOid, format: ObjectFormat) -> Result<OidBytes, SimGitError> {
    let expected = format.oid_len() as usize;
    let got = oid.bytes.len();
    if got != expected {
        return Err(SimGitError::InvalidOidLength { expected, got });
    }
    Ok(OidBytes::from_slice(&oid.bytes))
}
