#![no_main]

use libfuzzer_sys::fuzz_target;

use gossip_stdx::atomic_bitset::AtomicBitSet;

// Interprets a byte stream as an operation sequence against `AtomicBitSet`,
// checking every result against a `Vec<bool>` ground-truth model.
//
// Byte layout:
// - Byte 0 -> `bit_length` (clamped to 1..=255)
// - Remaining bytes as `(opcode, operand)` pairs:
//   - 0 -> `test_and_set(operand % bit_length)`
//   - 1 -> `is_set(operand % bit_length)`
//   - 2 -> `clear()`
//   - 3 -> `count()`
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let bit_length = (data[0] as usize).max(1);
    let bs = AtomicBitSet::empty(bit_length);
    let mut model = vec![false; bit_length];

    let ops = &data[1..];
    let mut i = 0;
    while i + 1 < ops.len() {
        let opcode = ops[i];
        let operand = ops[i + 1] as usize;
        i += 2;

        match opcode % 4 {
            // test_and_set
            0 => {
                let idx = operand % bit_length;
                let was_unset = bs.test_and_set(idx);
                let model_was_unset = !model[idx];
                model[idx] = true;
                assert_eq!(
                    was_unset, model_was_unset,
                    "test_and_set({idx}) mismatch: atomic={was_unset}, model={model_was_unset}"
                );
            }
            // is_set
            1 => {
                let idx = operand % bit_length;
                assert_eq!(bs.is_set(idx), model[idx], "is_set({idx}) mismatch");
            }
            // clear
            2 => {
                bs.clear();
                model.fill(false);
            }
            // count
            _ => {
                let expected: usize = model.iter().filter(|&&b| b).count();
                assert_eq!(
                    bs.count(),
                    expected,
                    "count() mismatch: atomic={}, model={expected}",
                    bs.count()
                );
            }
        }
    }

    // Final consistency check.
    let expected_count: usize = model.iter().filter(|&&b| b).count();
    assert_eq!(bs.count(), expected_count, "final count mismatch");
});
