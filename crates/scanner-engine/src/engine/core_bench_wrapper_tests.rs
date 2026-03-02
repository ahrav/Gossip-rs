use super::*;

#[test]
fn entropy_wrapper_reuses_table_for_same_max_len() {
    let input = b"entropy-data";
    let _ = bench_shannon_entropy(input, 64);

    let ptr_before = BENCH_ENTROPY_STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.max_len, 64);
        state.log2_table.as_ptr()
    });

    let _ = bench_entropy_gate_passes(3.0, 1, 64, input);

    let ptr_after = BENCH_ENTROPY_STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.max_len, 64);
        state.log2_table.as_ptr()
    });

    assert_eq!(ptr_before, ptr_after);
}

#[test]
fn merge_wrapper_keeps_capacity_for_smaller_followup_inputs() {
    let large: Vec<(u32, u32)> = (0..64).map(|i| (i * 4, i * 4 + 2)).collect();
    let small: Vec<(u32, u32)> = (0..4).map(|i| (i * 10, i * 10 + 1)).collect();

    let _ = bench_merge_ranges(&large, 0);
    let cap_after_large = BENCH_MERGE_STATE.with(|state| state.borrow().ranges.capacity());
    assert!(cap_after_large >= large.len());

    let _ = bench_merge_ranges(&small, 0);
    let cap_after_small = BENCH_MERGE_STATE.with(|state| state.borrow().ranges.capacity());
    assert_eq!(cap_after_small, cap_after_large);
}

#[test]
fn utf16_wrapper_reuses_capacity_for_same_max_out() {
    let input = [b'A', 0, b'B', 0];

    let _ = bench_decode_utf16le(&input, 8);
    let cap_before = BENCH_UTF16_STATE.with(|state| state.borrow().out.capacity());

    let _ = bench_decode_utf16le(&input, 8);
    let cap_after_same = BENCH_UTF16_STATE.with(|state| state.borrow().out.capacity());
    assert_eq!(cap_after_same, cap_before);

    let _ = bench_decode_utf16le(&input, 16);
    let cap_after_growth = BENCH_UTF16_STATE.with(|state| state.borrow().out.capacity());
    assert!(cap_after_growth >= 16);
}
