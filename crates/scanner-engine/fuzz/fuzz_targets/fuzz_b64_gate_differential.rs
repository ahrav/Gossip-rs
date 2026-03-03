#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
use std::sync::OnceLock;

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
    static REF_PATTERNS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    static GATE: OnceLock<Base64YaraGate> = OnceLock::new();

    // Fixed anchors for differential stability
    let anchors: &[&[u8]] = &[b"This program cannot", b"abc", b"test", b"\xff\xff\xff"];
    let min_len = 0usize;

    let patterns = REF_PATTERNS.get_or_init(|| {
        let mut set: BTreeSet<Vec<u8>> = BTreeSet::new();
        for a in anchors {
            for o in 0..3 {
                if let Some(p) = ref_yara_perm(a, o, min_len) {
                    set.insert(p);
                }
            }
        }
        set.into_iter().collect()
    });

    let cfg = Base64YaraGateConfig {
        min_pattern_len: min_len,
        ..Default::default()
    };

    let gate = GATE.get_or_init(|| Base64YaraGate::build(anchors.iter().copied(), cfg.clone()));

    // Gate must match the reference-pattern oracle
    let ours = gate.hits(data);
    let ref_oracle = oracle_hits(patterns, data, cfg.padding_policy, cfg.whitespace_policy);
    assert_eq!(ours, ref_oracle);
});
