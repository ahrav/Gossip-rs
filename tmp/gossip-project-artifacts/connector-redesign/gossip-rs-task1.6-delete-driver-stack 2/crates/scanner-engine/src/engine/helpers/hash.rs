//! Hashing helpers for decoded buffer deduplication.

/// Zero key for AEGIS-128L MAC, stored in `.rodata` to avoid per-call stack init.
const ZERO_KEY: [u8; 16] = [0u8; 16];

/// Collision-resistant 128-bit hash using AEGIS-128L MAC.
///
/// Design intent:
/// - We need a *fast* but *low-collision* fingerprint for decoded buffers.
/// - SipHash is strong but slower; non-crypto hashes are fast but risky.
/// - AEGIS-128L uses AES-NI on modern CPUs and yields a 128-bit MAC.
///
/// By fixing the key to zero and authenticating `bytes` as the message, we get
/// a deterministic 128-bit tag that behaves like a PRF. This is not a general-
/// purpose cryptographic hash, but it is collision-resistant enough for
/// in-process deduplication and avoids an extra dependency.
pub(crate) fn hash128(bytes: &[u8]) -> u128 {
    use aegis::aegis128l::Aegis128LMac;
    let mut mac = Aegis128LMac::<16>::new(&ZERO_KEY);
    mac.update(bytes);
    u128::from_le_bytes(mac.finalize())
}

/// Returns the smallest power of two greater than or equal to `v`.
///
/// # Behavior
/// - Returns 1 when `v == 0`.
pub(crate) fn pow2_at_least(v: usize) -> usize {
    v.next_power_of_two()
}

/// Converts a `u64` to `usize` with saturation on overflow.
pub(crate) fn u64_to_usize(v: u64) -> usize {
    if v > (usize::MAX as u64) {
        usize::MAX
    } else {
        v as usize
    }
}
