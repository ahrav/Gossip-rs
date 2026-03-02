//! Compatibility re-exports for scanner engine public API types.
//!
//! Scheduler modules were originally written against `crate::api::*` in the
//! scanner-rs monolith. Re-exporting here keeps extracted files unchanged
//! while routing all real implementations through `scanner-engine`.
pub use scanner_engine::{
    FileId, Finding, FindingRec, RuleSpec, TransformConfig, Tuning, ValidatorKind,
};
