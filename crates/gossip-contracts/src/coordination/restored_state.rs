//! Coordination state restored from an acquire/restore payload.

use crate::connector::Cursor;

use super::{CursorSemantics, ShardSpec};

/// Coordination state restored from an acquire/restore payload.
///
/// Groups the authoritative shard bounds, resume cursor, and cursor semantics
/// that downstream runtime stages need to execute ordered-content work without
/// a second coordination lookup.
///
/// Constructed from the coordination facade's acquire/restore response and
/// stored on `ShardLease` in the scanner runtime. Passed to
/// `OrderedContentRuntimeInput::new` to validate connector pages and derive
/// checkpoint cursors during scans.
///
/// The fields are immutable for the shard's lifetime; downstream execution
/// decides cursor advancement through checkpoint writes, not by mutating
/// this state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoredShardState {
    shard_spec: ShardSpec,
    resume_cursor: Cursor,
    cursor_semantics: CursorSemantics,
}

impl RestoredShardState {
    /// Construct restored shard state from its constituent parts.
    #[must_use]
    pub fn new(
        shard_spec: ShardSpec,
        resume_cursor: Cursor,
        cursor_semantics: CursorSemantics,
    ) -> Self {
        Self {
            shard_spec,
            resume_cursor,
            cursor_semantics,
        }
    }

    /// Authoritative shard bounds.
    #[must_use]
    pub fn shard_spec(&self) -> &ShardSpec {
        &self.shard_spec
    }

    /// Authoritative resume cursor.
    #[must_use]
    pub fn resume_cursor(&self) -> &Cursor {
        &self.resume_cursor
    }

    /// Coordination cursor semantics.
    #[must_use]
    pub fn cursor_semantics(&self) -> CursorSemantics {
        self.cursor_semantics
    }
}
