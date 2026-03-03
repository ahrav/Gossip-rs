#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

use scanner_engine::b64_yara_gate::{Base64YaraGate, Base64YaraGateConfig, GateState};

fuzz_target!(|data: &[u8]| {
    static GATE: OnceLock<Base64YaraGate> = OnceLock::new();
    let gate = GATE.get_or_init(|| {
        Base64YaraGate::build(
            [
                b"This program cannot".as_slice(),
                b"abc".as_slice(),
                b"test".as_slice(),
                b"\xff\xff\xff".as_slice(),
            ],
            Base64YaraGateConfig {
                min_pattern_len: 0,
                ..Default::default()
            },
        )
    });

    // Determinism: same input -> same result
    let a = gate.hits(data);
    let b = gate.hits(data);
    assert_eq!(a, b);

    // Streaming equivalence: split point derived from input
    let split = if data.is_empty() {
        0
    } else {
        (data[0] as usize) % (data.len() + 1)
    };

    let mut st = GateState::default();
    let s1 = gate.scan_with_state(&data[..split], &mut st);
    let s2 = gate.scan_with_state(&data[split..], &mut st);
    assert_eq!(a, s1 || s2);

    // Determinism in streaming, too
    let mut st2 = GateState::default();
    let t1 = gate.scan_with_state(&data[..split], &mut st2);
    let t2 = gate.scan_with_state(&data[split..], &mut st2);
    assert_eq!(s1 || s2, t1 || t2);
});
