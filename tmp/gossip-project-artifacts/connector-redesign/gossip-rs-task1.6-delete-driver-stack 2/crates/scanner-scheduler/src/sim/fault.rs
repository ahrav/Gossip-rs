//! Deterministic fault plans and injection hooks for simulation.
//!
//! Faults are keyed by path bytes and per-operation index so the same scenario
//! and schedule seeds reproduce identical behavior.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde::{Deserializer, Serializer};

/// Fault plan keyed by file path bytes.
///
/// Serialization encodes path bytes as lowercase hex strings under `per_file`
/// so artifacts remain JSON-compatible. Deserialization accepts hex or raw
/// UTF-8 strings for convenience.
#[derive(Clone, Debug)]
pub struct FaultPlan {
    pub per_file: BTreeMap<Vec<u8>, FileFaultPlan>,
}

/// Fault plan for a single file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileFaultPlan {
    /// Optional fault on open.
    pub open: Option<IoFault>,
    /// Per-read fault plan, indexed by read count (0-based).
    pub reads: Vec<ReadFault>,
    /// Optional cancellation after N reads.
    pub cancel_after_reads: Option<u32>,
}

/// Fault configuration for an individual read operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadFault {
    pub fault: Option<IoFault>,
    pub latency_ticks: u64,
    pub corruption: Option<Corruption>,
}

/// I/O fault kinds understood by the simulation runner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IoFault {
    /// Signal a generic I/O error. The runner treats any `ErrKind` as a
    /// permanent failure and skips the file. The `kind` field is reserved
    /// for future per-`ErrorKind` dispatch.
    ErrKind { kind: u16 },
    /// Return at most `max_len` bytes for the read.
    PartialRead { max_len: u32 },
    /// Emulate a single EINTR-style interruption.
    EIntrOnce,
}

/// Optional data corruption applied to read results.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Corruption {
    TruncateTo { new_len: u32 },
    FlipBit { offset: u32, mask: u8 },
    Overwrite { offset: u32, bytes: Vec<u8> },
}

#[derive(Serialize, Deserialize)]
struct FaultPlanSerde {
    per_file: BTreeMap<String, FileFaultPlan>,
}

impl Serialize for FaultPlan {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut per_file = BTreeMap::new();
        for (path, plan) in &self.per_file {
            per_file.insert(encode_path_hex(path), plan.clone());
        }
        FaultPlanSerde { per_file }.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FaultPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let helper = FaultPlanSerde::deserialize(deserializer)?;
        let mut per_file = BTreeMap::new();
        for (key, plan) in helper.per_file {
            let decoded = decode_path_hex(&key).map_err(serde::de::Error::custom)?;
            per_file.insert(decoded, plan);
        }
        Ok(FaultPlan { per_file })
    }
}

fn encode_path_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(hex_char(b >> 4));
        out.push(hex_char(b & 0x0f));
    }
    out
}

/// Decode a hex-encoded path, or fall back to raw UTF-8 bytes.
///
/// If the string is valid hex (even length, all hex chars), decode it.
/// Otherwise, treat the string as raw UTF-8 and return its bytes directly.
/// This allows JSON artifacts to use either `"666f6f"` or `"foo"` for paths.
fn decode_path_hex(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if bytes.len().is_multiple_of(2) && bytes.iter().all(|b| hex_val(*b).is_ok()) {
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut idx = 0;
        while idx < bytes.len() {
            let hi = hex_val(bytes[idx])?;
            let lo = hex_val(bytes[idx + 1])?;
            out.push((hi << 4) | lo);
            idx += 2;
        }
        return Ok(out);
    }
    Ok(bytes.to_vec())
}

fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => '0',
    }
}

fn hex_val(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hex path contains non-hex char".to_string()),
    }
}

/// Runtime fault injector that tracks per-file read indices.
#[derive(Clone, Debug)]
pub struct FaultInjector {
    plan: FaultPlan,
    read_idx: BTreeMap<Vec<u8>, u32>,
}

impl FaultInjector {
    /// Create a new injector from a deterministic fault plan.
    pub fn new(plan: FaultPlan) -> Self {
        Self {
            plan,
            read_idx: BTreeMap::new(),
        }
    }

    /// Retrieve the open fault for a path, if any.
    pub fn on_open(&mut self, path: &[u8]) -> Option<IoFault> {
        self.plan.per_file.get(path).and_then(|p| p.open.clone())
    }

    /// Retrieve the next read fault for a path.
    pub fn on_read(&mut self, path: &[u8]) -> ReadFault {
        let idx = self.read_idx.entry(path.to_vec()).or_insert(0);
        let i = *idx as usize;
        *idx = idx.saturating_add(1);

        self.plan
            .per_file
            .get(path)
            .and_then(|p| p.reads.get(i).cloned())
            .unwrap_or(ReadFault {
                fault: None,
                latency_ticks: 0,
                corruption: None,
            })
    }

    /// Return whether the file should be cancelled after `reads_done` reads.
    pub fn should_cancel(&self, path: &[u8], reads_done: u32) -> bool {
        self.plan
            .per_file
            .get(path)
            .and_then(|p| p.cancel_after_reads)
            .map(|n| reads_done >= n)
            .unwrap_or(false)
    }
}
