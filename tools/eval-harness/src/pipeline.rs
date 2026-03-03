//! Pipeline-level configuration shared across eval-harness modules.
//!
//! Keeps execution semantics in a core domain module so orchestration,
//! matching, and report serialization can depend on the same source of truth.

use serde::{Deserialize, Serialize};

/// Deduplication semantics applied before matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DedupMode {
    /// Keep one finding per `(path, byte_start, byte_end, rule)`.
    #[default]
    ByRule,
    /// Keep one finding per `(path, byte_start, byte_end)` across all rules.
    AcrossRules,
}

/// Processing flags that affect finding/matching semantics in eval runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EvalPipelineConfig {
    /// Whether cross-rule dedup was applied before matching.
    pub cross_rule_dedup: bool,
}

impl EvalPipelineConfig {
    /// Convert wire-level flags to the internal dedup strategy enum.
    #[must_use]
    pub fn dedup_mode(&self) -> DedupMode {
        if self.cross_rule_dedup {
            DedupMode::AcrossRules
        } else {
            DedupMode::ByRule
        }
    }
}
