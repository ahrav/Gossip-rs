use super::*;

/// Build a 256-bit anchor byte set containing exactly the given bytes.
fn make_anchor_set(bytes: &[u8]) -> [u64; 4] {
    let mut set = [0u64; 4];
    for &b in bytes {
        set[(b >> 6) as usize] |= 1u64 << (b & 63);
    }
    set
}

// Boundary coverage for `%XX` handling in the standalone gate helper.

#[test]
fn gate_triplet_at_end_of_buffer() {
    // %20 decodes to 0x20 (space). Anchor set contains space.
    let set = make_anchor_set(b" ");
    // Buffer is exactly the 3-byte triplet — nothing before or after.
    assert!(
        url_percent_gate_check(&set, false, b"%20"),
        "gate must detect %XX triplet at the very end of the buffer"
    );
}

#[test]
fn gate_triplet_at_end_after_plain_bytes() {
    let set = make_anchor_set(b"k");
    // 0x6B == 'k'
    assert!(
        url_percent_gate_check(&set, false, b"hello%6B"),
        "gate must detect %XX triplet at end preceded by plain text"
    );
}

#[test]
fn gate_triplet_not_at_boundary_still_works() {
    // Sanity: triplet NOT at the boundary should still work.
    let set = make_anchor_set(b" ");
    assert!(url_percent_gate_check(&set, false, b"%20xyz"));
}

#[test]
fn gate_no_anchor_bytes_returns_false() {
    let set = make_anchor_set(b"A");
    // %20 decodes to space, which is NOT in the anchor set.
    assert!(!url_percent_gate_check(&set, false, b"%20"));
}

#[test]
fn gate_plus_to_space_without_percent_triplet() {
    let set = make_anchor_set(b" ");
    assert!(
        url_percent_gate_check(&set, true, b"TOK+ABCD"),
        "plus-to-space must pass even when no %XX escapes are present"
    );
    assert!(
        !url_percent_gate_check(&set, false, b"TOK+ABCD"),
        "without plus-to-space, '+' should not affect the gate"
    );
}

#[test]
fn gate_empty_anchor_set_returns_true() {
    let empty = [0u64; 4];
    assert!(
        url_percent_gate_check(&empty, false, b"anything"),
        "empty anchor set is conservative — always returns true"
    );
}

// ---- decode_hex_pair coverage ----

#[test]
fn hex_pair_valid_digits() {
    assert_eq!(decode_hex_pair(b'0', b'0'), Some(0x00));
    assert_eq!(decode_hex_pair(b'F', b'F'), Some(0xFF));
    assert_eq!(decode_hex_pair(b'f', b'f'), Some(0xFF));
    assert_eq!(decode_hex_pair(b'4', b'1'), Some(0x41)); // 'A'
    assert_eq!(decode_hex_pair(b'6', b'B'), Some(0x6B)); // 'k'
}

#[test]
fn hex_pair_mixed_case() {
    assert_eq!(decode_hex_pair(b'a', b'B'), Some(0xAB));
    assert_eq!(decode_hex_pair(b'C', b'd'), Some(0xCD));
}

#[test]
fn hex_pair_invalid_hi() {
    assert_eq!(decode_hex_pair(b'G', b'0'), None);
    assert_eq!(decode_hex_pair(b'/', b'0'), None); // just below '0'
    assert_eq!(decode_hex_pair(b':', b'0'), None); // just above '9'
}

#[test]
fn hex_pair_invalid_lo() {
    assert_eq!(decode_hex_pair(b'0', b'g'), None);
    assert_eq!(decode_hex_pair(b'0', b' '), None);
}

// ---- gate edge cases ----

#[test]
fn gate_truncated_triplet_at_end() {
    let set = make_anchor_set(b" ");
    // Buffer ends with `%2` — not enough bytes to form a triplet.
    // Conservatively returns true (the truncated escape might decode to
    // an anchor byte with more data).
    assert!(url_percent_gate_check(&set, false, b"hello%2"));
}

#[test]
fn gate_percent_with_invalid_hex() {
    let set = make_anchor_set(&[0x00]); // any byte would match 0x00
    // `%ZZ` is not valid hex — should skip, not panic.
    assert!(!url_percent_gate_check(&set, false, b"%ZZ"));
}

#[test]
fn gate_empty_buffer() {
    let set = make_anchor_set(b"A");
    assert!(!url_percent_gate_check(&set, false, b""));
}
