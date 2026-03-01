//! FNV-1a 64-bit hashing helpers for deterministic fingerprinting.
//!
//! These form a self-contained, deterministic hashing toolkit used by both
//! page signatures and finding fingerprints across `gossip-engine` and
//! `gossip-worker`. The contract is simple:
//!
//! - All multi-byte values are mixed in little-endian order.
//! - Variable-length fields are length-prefixed before content so that
//!   ("ab", "c") hashes differently from ("a", "bc").
//! - `Option<&[u8]>` is domain-separated with a tag byte (0 = None, 1 = Some).
//!
//! FNV-1a was chosen over `DefaultHasher` / SipHash for cross-platform
//! determinism — identical inputs always produce identical hashes regardless
//! of target architecture or Rust version.
//!
//! Reference: <http://www.isthe.com/chongo/tech/comp/fnv/>

/// FNV-1a 64-bit offset basis.
pub const FNV_OFFSET: u64 = 0xcbf29ce484222325;

/// FNV-1a 64-bit prime multiplier.
pub const FNV_PRIME: u64 = 0x100000001b3;

/// Mix a single byte into the running FNV-1a state.
#[inline]
pub fn fnv_mix_byte(sig: &mut u64, byte: u8) {
    *sig ^= u64::from(byte);
    *sig = sig.wrapping_mul(FNV_PRIME);
}

/// Mix a `u64` as 8 little-endian bytes.
#[inline]
pub fn fnv_mix_u64(sig: &mut u64, value: u64) {
    for byte in value.to_le_bytes() {
        fnv_mix_byte(sig, byte);
    }
}

/// Mix a byte slice, length-prefixed to avoid collisions between
/// concatenations that share a common prefix.
///
/// Bulk processing in 8-byte words reduces per-byte overhead for large
/// payloads without changing the hash result.
#[inline]
pub fn fnv_mix_bytes(sig: &mut u64, bytes: &[u8]) {
    fnv_mix_u64(sig, bytes.len() as u64);
    let full_chunks = bytes.len() / 8;
    let (bulk, tail) = bytes.split_at(full_chunks * 8);
    for chunk in bulk.chunks_exact(8) {
        let word = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        fnv_mix_u64(sig, word);
    }
    for byte in tail {
        fnv_mix_byte(sig, *byte);
    }
}

/// Mix an optional byte slice with a tag byte for domain separation.
#[inline]
pub fn fnv_mix_opt_bytes(sig: &mut u64, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            fnv_mix_byte(sig, 1);
            fnv_mix_bytes(sig, bytes);
        }
        None => fnv_mix_byte(sig, 0),
    }
}

#[cfg(test)]
#[path = "fnv_tests.rs"]
mod tests;
