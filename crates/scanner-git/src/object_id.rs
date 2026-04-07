//! Object ID types for Git scanning.
//!
//! These types provide fixed-size, zero-heap storage for SHA-1 and SHA-256
//! object identifiers with stable layout guarantees.
//!
//! # Ordering Semantics
//! - `OidBytes` compares lexicographically on the truncated slice
//!   (`bytes[0..len]`). This means a SHA-1 OID that is a prefix of a SHA-256
//!   OID sorts before the SHA-256 OID.
//! - Ordering is format-agnostic; only the byte content and length matter.

use std::fmt;
use std::hash::{Hash, Hasher};

/// Object ID format determines OID byte length.
///
/// The discriminants are stable and may be used for compact serialization.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ObjectFormat {
    /// SHA-1 object IDs (20 bytes).
    #[default]
    Sha1 = 1,
    /// SHA-256 object IDs (32 bytes).
    Sha256 = 2,
}

impl ObjectFormat {
    /// Returns the byte length for OIDs in this format.
    #[inline]
    #[must_use]
    pub const fn oid_len(self) -> u8 {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    /// Returns the hex string length for OIDs in this format.
    #[inline]
    #[must_use]
    pub const fn hex_len(self) -> u8 {
        self.oid_len() * 2
    }
}

/// Fixed-size storage for SHA-1 or SHA-256 object IDs.
///
/// This is a compact, layout-stable container that avoids heap allocation.
/// The length discriminator is stored alongside the bytes so callers can
/// parse raw slices without knowing the format in advance.
///
/// # Invariants
/// - `len` is always 20 or 32
/// - Only `bytes[0..len]` contains valid data
/// - `bytes[len..32]` is always zero-padded
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OidBytes {
    len: u8,
    bytes: [u8; 32],
}

impl OidBytes {
    /// Maximum OID length (SHA-256).
    pub const MAX_LEN: u8 = 32;
    /// SHA-1 OID length.
    pub const SHA1_LEN: u8 = 20;
    /// SHA-256 OID length.
    pub const SHA256_LEN: u8 = 32;

    /// Creates a new `OidBytes` for SHA-1 (20 bytes).
    #[inline]
    #[must_use]
    pub fn sha1(bytes: [u8; 20]) -> Self {
        let mut storage = [0u8; 32];
        storage[..20].copy_from_slice(&bytes);
        Self {
            len: 20,
            bytes: storage,
        }
    }

    /// Creates a new `OidBytes` for SHA-256 (32 bytes).
    #[inline]
    #[must_use]
    pub fn sha256(bytes: [u8; 32]) -> Self {
        Self { len: 32, bytes }
    }

    /// Creates `OidBytes` from a slice.
    ///
    /// This is intended for trusted inputs where invalid lengths indicate
    /// a programming error.
    ///
    /// # Panics
    ///
    /// Panics if `bytes.len()` is not 20 or 32.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::try_from_slice(bytes).expect("OID must be 20 or 32 bytes")
    }

    /// Creates `OidBytes` from a slice, returning `None` for invalid lengths.
    ///
    /// Use this for untrusted input where panicking is undesirable.
    #[must_use]
    pub fn try_from_slice(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            20 => {
                let mut storage = [0u8; 32];
                storage[..20].copy_from_slice(bytes);
                Some(Self {
                    len: 20,
                    bytes: storage,
                })
            }
            32 => {
                let mut storage = [0u8; 32];
                storage.copy_from_slice(bytes);
                Some(Self {
                    len: 32,
                    bytes: storage,
                })
            }
            _ => None,
        }
    }

    /// Returns the OID bytes as a slice.
    ///
    /// The returned slice length is always 20 or 32.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        debug_assert!(
            self.len == Self::SHA1_LEN || self.len == Self::SHA256_LEN,
            "invalid OID len: {}",
            self.len
        );
        &self.bytes[..self.len as usize]
    }

    /// Returns the length of the OID (20 or 32).
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u8 {
        self.len
    }

    /// Returns the full 32-byte backing array (zero-padded for SHA-1).
    ///
    /// Used by checkpoint serialization to avoid heap allocation — the
    /// caller stores the raw array alongside the length discriminant.
    #[inline]
    #[must_use]
    pub const fn raw_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Reconstruct an `OidBytes` from a raw length + backing array pair.
    ///
    /// # Panics
    ///
    /// Panics if `len` is not 20 or 32.
    ///
    /// Callers deserializing from untrusted storage should validate the length
    /// before calling this function. The checkpoint module validates OID lengths
    /// during `from_loaded`, ensuring the assert never fires for well-formed
    /// checkpoint blobs.
    #[inline]
    #[must_use]
    pub fn from_raw(len: u8, bytes: [u8; 32]) -> Self {
        assert!(
            len == Self::SHA1_LEN || len == Self::SHA256_LEN,
            "invalid OID len: {len}"
        );
        let mut bytes = bytes;
        // Enforce the zero-padding invariant documented on the struct:
        // only `bytes[0..len]` carries valid data.
        if len == Self::SHA1_LEN {
            bytes[Self::SHA1_LEN as usize..].fill(0);
        }
        Self { len, bytes }
    }

    /// Returns true if the OID is empty.
    ///
    /// OIDs are always 20 or 32 bytes; this is provided for API symmetry
    /// with slice-like types and always returns `false` for valid instances.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the object format for this OID.
    ///
    /// This relies on the invariant that `len` is either 20 or 32.
    #[inline]
    #[must_use]
    pub const fn format(&self) -> ObjectFormat {
        if self.len == 20 {
            ObjectFormat::Sha1
        } else {
            ObjectFormat::Sha256
        }
    }

    /// Returns true if this is a zero OID (all bytes are 0).
    ///
    /// This check is not constant-time; do not use it for secret material.
    #[must_use]
    pub fn is_null(&self) -> bool {
        self.as_slice().iter().all(|&b| b == 0)
    }

    /// Wire-encoded length: 1 byte length prefix + 32 bytes payload
    /// (OID bytes followed by zero-padding for SHA-1).
    pub const WIRE_LEN: usize = 33;

    /// Encode to the fixed-size wire format used by `FindingEvent::blob_oid`.
    ///
    /// Byte 0 stores the OID length (20 or 32), bytes 1..=len store the raw
    /// OID bytes, and the remainder is zero-padded.
    #[inline]
    #[must_use]
    pub fn encode_to_wire(&self) -> [u8; Self::WIRE_LEN] {
        let mut buf = [0u8; Self::WIRE_LEN];
        let len = self.len as usize;
        buf[0] = self.len;
        buf[1..=len].copy_from_slice(self.as_slice());
        buf
    }

    /// Decode from the fixed-size wire format.
    ///
    /// Returns `None` if the length byte is invalid (not 20 or 32),
    /// trailing bytes are non-zero, or the payload fails validation.
    #[must_use]
    pub fn decode_from_wire(raw: [u8; Self::WIRE_LEN]) -> Option<Self> {
        let len = raw[0] as usize;
        if len != Self::SHA1_LEN as usize && len != Self::SHA256_LEN as usize {
            return None;
        }
        if raw[(len + 1)..].iter().any(|&b| b != 0) {
            return None;
        }
        Self::try_from_slice(&raw[1..=len])
    }
}

impl Default for OidBytes {
    fn default() -> Self {
        // Default to the SHA-1 "null" OID to keep a compact, deterministic
        // zero value without requiring heap allocation.
        Self {
            len: 20,
            bytes: [0u8; 32],
        }
    }
}

impl fmt::Debug for OidBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OidBytes({:02x?})", self.as_slice())
    }
}

impl fmt::Display for OidBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Lowercase hex, matching Git's canonical OID rendering.
        for byte in self.as_slice() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl PartialEq for OidBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for OidBytes {}

impl Hash for OidBytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl PartialOrd for OidBytes {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OidBytes {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: () = {
        assert!(std::mem::size_of::<OidBytes>() == 33);
        assert!(std::mem::size_of::<ObjectFormat>() == 1);

        assert!(std::mem::align_of::<OidBytes>() == 1);
        assert!(std::mem::align_of::<ObjectFormat>() == 1);
    };

    #[test]
    fn oid_bytes_sha1() {
        let bytes = [0xab; 20];
        let oid = OidBytes::sha1(bytes);

        assert_eq!(oid.len(), 20);
        assert_eq!(oid.as_slice(), &bytes);
        assert_eq!(oid.format(), ObjectFormat::Sha1);
        assert!(oid.bytes[20..].iter().all(|&b| b == 0));
    }

    #[test]
    fn oid_bytes_sha256() {
        let bytes = [0xcd; 32];
        let oid = OidBytes::sha256(bytes);

        assert_eq!(oid.len(), 32);
        assert_eq!(oid.as_slice(), &bytes);
        assert_eq!(oid.format(), ObjectFormat::Sha256);
    }

    #[test]
    fn oid_bytes_ordering() {
        let a = OidBytes::sha1([0x00; 20]);
        let b = OidBytes::sha1([0x01; 20]);
        let c = OidBytes::sha1([0xff; 20]);

        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn oid_bytes_null_check() {
        let null = OidBytes::sha1([0x00; 20]);
        let non_null = OidBytes::sha1([0x01; 20]);

        assert!(null.is_null());
        assert!(!non_null.is_null());
    }

    #[test]
    fn oid_bytes_try_from_slice() {
        let sha1 = OidBytes::try_from_slice(&[0xab; 20]);
        assert!(sha1.is_some());
        assert_eq!(sha1.unwrap().len(), 20);

        let sha256 = OidBytes::try_from_slice(&[0xcd; 32]);
        assert!(sha256.is_some());
        assert_eq!(sha256.unwrap().len(), 32);

        assert!(OidBytes::try_from_slice(&[0u8; 0]).is_none());
        assert!(OidBytes::try_from_slice(&[0u8; 10]).is_none());
        assert!(OidBytes::try_from_slice(&[0u8; 21]).is_none());
        assert!(OidBytes::try_from_slice(&[0u8; 64]).is_none());
    }

    #[test]
    fn oid_bytes_eq_hash_consistency() {
        let a = OidBytes::sha1([0xab; 20]);
        let b = OidBytes::sha1([0xab; 20]);

        assert_eq!(a, b);

        use std::collections::hash_map::DefaultHasher;
        let hash_a = {
            let mut h = DefaultHasher::new();
            a.hash(&mut h);
            h.finish()
        };
        let hash_b = {
            let mut h = DefaultHasher::new();
            b.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn oid_bytes_cross_format_ordering() {
        let sha1 = OidBytes::sha1([0xab; 20]);
        let sha256 = OidBytes::sha256([0xab; 32]);

        assert!(sha1 < sha256);
    }

    #[test]
    #[should_panic(expected = "OID must be 20 or 32 bytes")]
    fn oid_bytes_invalid_len() {
        let _ = OidBytes::from_slice(&[0u8; 10]);
    }

    #[test]
    fn wire_round_trip_sha1() {
        let oid = OidBytes::sha1([0xAB; 20]);
        assert_eq!(OidBytes::decode_from_wire(oid.encode_to_wire()), Some(oid));
    }

    #[test]
    fn wire_round_trip_sha256() {
        let oid = OidBytes::sha256([0xCD; 32]);
        assert_eq!(OidBytes::decode_from_wire(oid.encode_to_wire()), Some(oid));
    }

    #[test]
    fn wire_decode_rejects_invalid_length() {
        let mut raw = [0u8; OidBytes::WIRE_LEN];
        raw[0] = 21;
        assert!(OidBytes::decode_from_wire(raw).is_none());
    }

    #[test]
    fn wire_decode_rejects_nonzero_padding() {
        let oid = OidBytes::sha1([0x11; 20]);
        let mut raw = oid.encode_to_wire();
        raw[22] = 0xFF;
        assert!(OidBytes::decode_from_wire(raw).is_none());
    }

    #[test]
    fn wire_decode_rejects_zero_length() {
        assert!(OidBytes::decode_from_wire([0u8; OidBytes::WIRE_LEN]).is_none());
    }
}
