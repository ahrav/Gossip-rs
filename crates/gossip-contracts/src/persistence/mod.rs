//! Done-ledger, findings-sink traits, and the commit protocol typestate machine.
//!
//! This module will define the persistence boundary — traits for recording
//! completed work (done-ledger), emitting findings, and the typestate
//! machine that enforces the commit protocol invariants at compile time.
