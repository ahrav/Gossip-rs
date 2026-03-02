//! Minimal event/source compatibility module for scheduler extraction.
//!
//! Step 2a keeps the scheduler event plumbing intact behind a lightweight
//! compatibility layer. Step 2b will replace this with split `CoreEvent` and
//! git-specific event contracts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Fs,
    Git,
}

pub mod events;
