#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use scanner_engine::b64_yara_gate::{Base64YaraGate, Base64YaraGateConfig};

fn ref_yara_perm(anchor: &[u8], offset: usize, min_len: usize) -> Option<Vec<u8>> {
    if anchor.is_empty() || offset >= 3 {
        return None;
    }

    let mut prefixed = vec![0u8; offset];
    prefixed.extend_from_slice(anchor);

    let enc = STANDARD.encode(&prefixed).into_bytes();

    let left = match offset {
        0 => 0usize,
        1 => 2usize,
        2 => 3usize,
        _ => unreachable!(),
    };

    let rem = prefixed.len() % 3;
    let right = match rem {
        0 => 0usize,
        1 => 3usize,
        2 => 2usize,
        _ => unreachable!(),
    };

    if enc.len() <= left + right {
        return None;
    }

    let pat = enc[left..(enc.len() - right)].to_vec();
    if pat.len() < min_len {
        return None;
    }
    Some(pat)
}

fn oracle_hits(
    patterns: &[Vec<u8>],
    encoded: &[u8],
    padding_policy: scanner_engine::b64_yara_gate::PaddingPolicy,
    whitespace_policy: scanner_engine::b64_yara_gate::WhitespacePolicy,
) -> bool {
    let mut cur: Vec<u8> = Vec::new();

    let check_seg = |seg: &[u8]| -> bool {
        for pat in patterns {
            if pat.is_empty() {
                return true;
            }
            if pat.len() <= seg.len() && seg.windows(pat.len()).any(|w| w == pat.as_slice()) {
                return true;
            }
        }
        false
    };

    for &b in encoded {
        let is_ws = match whitespace_policy {
            scanner_engine::b64_yara_gate::WhitespacePolicy::Rfc4648 => {
                matches!(b, b' ' | b'\n' | b'\r' | b'\t')
            }
            scanner_engine::b64_yara_gate::WhitespacePolicy::AsciiWhitespace => {
                b.is_ascii_whitespace()
            }
        };

        if is_ws {
            continue;
        }
        if b == b'=' {
            if !cur.is_empty() && check_seg(&cur) {
                return true;
            }
            cur.clear();
            match padding_policy {
                scanner_engine::b64_yara_gate::PaddingPolicy::StopAndHalt => {
                    return false;
                }
                scanner_engine::b64_yara_gate::PaddingPolicy::ResetAndContinue => {
                    continue;
                }
            }
        }

        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => cur.push(b),
            b'-' => cur.push(b'+'),
            b'_' => cur.push(b'/'),
            _ => {
                if !cur.is_empty() && check_seg(&cur) {
                    return true;
                }
                cur.clear();
            }
        }
    }

    if !cur.is_empty() {
        return check_seg(&cur);
    }
    false
}

fuzz_target!(|data: &[u8]| {
    // Parse fuzz input into:
    // - min_len in [0..=15]
    // - up to 4 anchors, each up to 32 bytes
    // - remaining bytes are the "encoded" scan input
    if data.len() < 2 {
        return;
    }

    let min_len = (data[0] & 0x0f) as usize;
    let anchor_count = (data[1] % 5) as usize; // 0..=4
    let mut idx = 2usize;

    let mut anchors: Vec<Vec<u8>> = Vec::new();
    for _ in 0..anchor_count {
        if idx >= data.len() {
            break;
        }
        let len = (data[idx] % 33) as usize; // 0..=32
        idx += 1;
        if idx + len > data.len() {
            break;
        }
        if len != 0 {
            anchors.push(data[idx..idx + len].to_vec());
        }
        idx += len;
    }

    let encoded = &data[idx..];

    // Build gate from anchors
    let anchor_slices: Vec<&[u8]> = anchors.iter().map(|a| a.as_slice()).collect();
    let cfg = Base64YaraGateConfig {
        min_pattern_len: min_len,
        ..Default::default()
    };

    let gate = Base64YaraGate::build(anchor_slices.iter().copied(), cfg.clone());

    // Build reference patterns from the same anchors using base64 crate oracle
    let mut set: BTreeSet<Vec<u8>> = BTreeSet::new();
    for a in &anchor_slices {
        for o in 0..3 {
            if let Some(p) = ref_yara_perm(a, o, min_len) {
                set.insert(p);
            }
        }
    }
    let patterns: Vec<Vec<u8>> = set.into_iter().collect();

    let ours = gate.hits(encoded);
    let ref_oracle = oracle_hits(
        &patterns,
        encoded,
        cfg.padding_policy,
        cfg.whitespace_policy,
    );
    assert_eq!(ours, ref_oracle);
});
