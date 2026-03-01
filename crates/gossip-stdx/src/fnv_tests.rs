use super::*;

#[test]
fn chunk_optimization_matches_byte_by_byte() {
    // Verify the u64-chunked fnv_mix_bytes produces the same result
    // as processing one byte at a time.
    let data = b"hello, this is a 25-byte string for testing chunked FNV";

    // Chunked path (current implementation).
    let mut sig_chunked = FNV_OFFSET;
    fnv_mix_bytes(&mut sig_chunked, data);

    // Byte-at-a-time reference.
    let mut sig_ref = FNV_OFFSET;
    fnv_mix_u64(&mut sig_ref, data.len() as u64);
    for byte in data {
        fnv_mix_byte(&mut sig_ref, *byte);
    }

    assert_eq!(
        sig_chunked, sig_ref,
        "chunked and byte-at-a-time must agree"
    );
}

#[test]
fn domain_separation_none_vs_some_empty() {
    // None and Some(b"") must hash differently so empty tokens are
    // distinguishable from absent tokens in page signatures.
    let mut sig_none = FNV_OFFSET;
    fnv_mix_opt_bytes(&mut sig_none, None);

    let mut sig_empty = FNV_OFFSET;
    fnv_mix_opt_bytes(&mut sig_empty, Some(b""));

    assert_ne!(
        sig_none, sig_empty,
        "None and Some(empty) must produce different hashes"
    );
}

#[test]
fn length_prefix_prevents_concatenation_collision() {
    // "ab" + "c" must differ from "a" + "bc".
    let mut sig1 = FNV_OFFSET;
    fnv_mix_bytes(&mut sig1, b"ab");
    fnv_mix_bytes(&mut sig1, b"c");

    let mut sig2 = FNV_OFFSET;
    fnv_mix_bytes(&mut sig2, b"a");
    fnv_mix_bytes(&mut sig2, b"bc");

    assert_ne!(
        sig1, sig2,
        "different field splits must produce different hashes"
    );
}

#[test]
fn empty_input_produces_deterministic_result() {
    let mut sig1 = FNV_OFFSET;
    fnv_mix_bytes(&mut sig1, b"");

    let mut sig2 = FNV_OFFSET;
    fnv_mix_bytes(&mut sig2, b"");

    assert_eq!(sig1, sig2);
    // After mixing empty bytes, sig should differ from bare offset
    // because we still mix the length (0).
    assert_ne!(sig1, FNV_OFFSET);
}

#[test]
fn u64_mixing_is_deterministic() {
    let mut sig1 = FNV_OFFSET;
    fnv_mix_u64(&mut sig1, 42);

    let mut sig2 = FNV_OFFSET;
    fnv_mix_u64(&mut sig2, 42);

    assert_eq!(sig1, sig2);
}

#[test]
fn different_u64_values_produce_different_hashes() {
    let mut sig1 = FNV_OFFSET;
    fnv_mix_u64(&mut sig1, 42);

    let mut sig2 = FNV_OFFSET;
    fnv_mix_u64(&mut sig2, 43);

    assert_ne!(sig1, sig2);
}
