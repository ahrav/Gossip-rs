//! Compatibility re-exports for scanner engine public API types.
//!
//! Scheduler modules were originally written against `crate::api::*` in the
//! scanner-rs monolith. Re-exporting here keeps extracted files unchanged
//! while routing all real implementations through `scanner-engine`.
//! This module is intentionally a thin shim and does not define scheduler-local
//! API types.
pub use scanner_engine::{
    AnchorPolicy, DecodeStep, FileId, Finding, FindingRec, Gate, RuleSpec, StepId, TransformConfig,
    TransformId, TransformMode, Tuning, ValidatorKind, STEP_ROOT,
};
