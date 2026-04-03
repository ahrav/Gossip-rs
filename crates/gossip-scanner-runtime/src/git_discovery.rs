//! Static Git repository discovery source for payload-backed one-target shards.
//!
//! [`StaticGitRepoDiscoverySource`] is the minimal [`GitRepoDiscoverySource`]
//! implementation for repo-frontier shards whose payload already carries one
//! normalized [`GitRepoTarget`]. The source never performs control-plane
//! lookups or mirror checks; it only decides whether that target should be
//! emitted for the current shard and cursor.
//!
//! Resume is key-authoritative: [`Cursor::last_key`] decides whether the target
//! is already complete, and connector tokens are ignored because a single
//! payload target has no extra provider-side continuation state.
//!
//! ## Surface overview
//!
//! | Item | Role |
//! |------|------|
//! | [`StaticGitRepoDiscoverySource`] | Emit-once payload-backed discovery source |
//! | [`StaticGitRepoDiscoverySource::new`] | Construct the source from one normalized target |
//! | [`GitRepoDiscoverySource::discover_page`] | Return one validated terminal page or `Ok(None)` |
//! | [`GitRepoDiscoverySource::choose_split_point`] | Always returns `Ok(None)` for one-target shards |

use gossip_contracts::{
    connector::git::{GitDiscoveryCapabilities, GitRepoDiscoverySource, GitRepoTarget},
    connector::{Budgets, Cursor, EnumerateError, ItemKey, PageBuf, PageState, PagingCapabilities},
    coordination::ShardSpec,
};

/// Minimal payload-backed [`GitRepoDiscoverySource`] for one-target shards.
///
/// The source owns one normalized [`GitRepoTarget`] and an `emitted` flag that
/// enforces an emit-once state machine. The target may be returned exactly
/// once, and later calls return `Ok(None)` after either successful emission or
/// a cursor that already proves the target is complete.
///
/// `&mut self` on the trait provides the single-owner mutability needed for
/// that state machine without interior synchronization.
#[derive(Debug)]
pub struct StaticGitRepoDiscoverySource {
    target: GitRepoTarget,
    emitted: bool,
}

impl StaticGitRepoDiscoverySource {
    /// Construct a one-target discovery source.
    ///
    /// The returned source owns `target` and may emit it at most once. The
    /// caller supplies the already-normalized `GitRepoTarget`; this type only
    /// applies shard-bound filtering and cursor-based completion checks.
    #[must_use]
    pub fn new(target: GitRepoTarget) -> Self {
        Self {
            target,
            emitted: false,
        }
    }
}

impl GitRepoDiscoverySource for StaticGitRepoDiscoverySource {
    /// Return static discovery capabilities for one-target payload-backed shards.
    ///
    /// Pages are ordered by the carried [`GitRepoTarget`]'s canonical
    /// [`gossip_contracts::connector::git::RepoKey`], there is no opaque resume
    /// token to preserve across calls, and the source never proposes split
    /// points because one-target shards have no interior split geometry.
    fn capabilities(&self) -> GitDiscoveryCapabilities {
        GitDiscoveryCapabilities {
            paging: PagingCapabilities {
                ordered_keys: true,
                resumable: false,
                splittable: false,
            },
        }
    }

    /// Return the carried target exactly once when it still belongs to the remaining shard suffix.
    ///
    /// Three observable outcomes:
    ///
    /// - `Ok(Some(PageBuf))` with one terminal item on the first in-range call;
    /// - `Ok(None)` when the target was already emitted, is outside the shard,
    ///   or a cursor at/past the target key proves completion;
    /// - `Err(EnumerateError)` (permanent) when [`PageBuf::try_new_validated`]
    ///   rejects the page, indicating invalid local runtime state rather than a
    ///   retryable remote condition.
    ///
    /// Any opaque token on `cursor` is ignored.
    fn discover_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<PageBuf<GitRepoTarget>>, EnumerateError> {
        if self.emitted {
            return Ok(None);
        }

        // Cursor check is stateless: a covering cursor always yields Ok(None)
        // without touching `emitted`, so the source stays reusable across
        // cursor resets (e.g. shard reassignment with a fresh cursor).
        if cursor_covers_target(cursor, &self.target) {
            return Ok(None);
        }

        if !shard.contains_key(self.target.repo_key().as_bytes()) {
            return Ok(None);
        }

        // Defensive: shard.contains_key already verified the target is in range,
        // so try_new_validated should not reject the page under normal conditions.
        let page = PageBuf::try_new_validated(
            vec![self.target.clone()],
            PageState::Complete,
            shard.key_range_start(),
            shard.key_range_end(),
        )
        .map_err(|err| {
            EnumerateError::permanent(format!("static git discovery produced invalid page: {err}"))
        })?;

        self.emitted = true;
        Ok(Some(page))
    }

    /// Return no split hint for one-target shard geometry.
    ///
    /// The payload carries exactly one repository target, so there is no
    /// interior key boundary that can split the remaining work safely.
    fn choose_split_point(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        Ok(None)
    }
}

fn cursor_covers_target(cursor: &Cursor, target: &GitRepoTarget) -> bool {
    cursor
        .last_key()
        .is_some_and(|last_key| last_key >= target.repo_key().as_item_key())
}

#[cfg(test)]
mod tests {
    use gossip_contracts::{
        connector::git::{RepoKey, RepoLocator},
        connector::{TokenBytes, validate_filled_page, validate_page_sequence},
    };
    use proptest::prelude::*;
    use rstest::rstest;

    use super::*;

    /// Build a deterministic discovery target for tests.
    fn make_test_target(key_bytes: &[u8]) -> GitRepoTarget {
        GitRepoTarget::new(
            RepoKey::try_from_slice(key_bytes).expect("repo key"),
            RepoLocator::local_path("/tmp/acme/repo.git"),
        )
        .with_display_name("acme/repo")
    }

    /// Construct a validated page budget for static discovery tests.
    fn budgets() -> Budgets {
        Budgets::try_new(16, 16 * 1024, None).expect("budgets")
    }

    /// Construct opaque token bytes for cursor tests.
    fn token(bytes: &[u8]) -> TokenBytes {
        TokenBytes::try_from_slice(bytes).expect("token bytes")
    }

    /// Build a lexicographically greater byte string for successor-style test keys.
    fn successor_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut next = bytes.to_vec();
        next.push(0);
        next
    }

    /// First in-range discovery call emits one complete page for the carried target.
    #[test]
    fn discover_page_initial_call_emits_single_target() {
        let target = make_test_target(b"git:repo:a");
        let mut discovery = StaticGitRepoDiscoverySource::new(target.clone());

        let page = discovery
            .discover_page(&ShardSpec::unbounded(), &Cursor::initial(), budgets())
            .expect("discover_page succeeds")
            .expect("target should emit");

        assert_eq!(page.len(), 1);
        assert_eq!(page.state(), &PageState::Complete);
        assert_eq!(&page.items()[0], &target);
    }

    /// The source never re-emits the carried target after a successful emission.
    #[test]
    fn discover_page_second_call_returns_none() {
        let target = make_test_target(b"git:repo:b");
        let mut discovery = StaticGitRepoDiscoverySource::new(target);

        let first = discovery
            .discover_page(&ShardSpec::unbounded(), &Cursor::initial(), budgets())
            .expect("first call succeeds");
        assert!(first.is_some(), "first call should emit the target");

        let second = discovery
            .discover_page(&ShardSpec::unbounded(), &Cursor::initial(), budgets())
            .expect("second call succeeds");
        assert!(second.is_none(), "second call must not re-emit");
    }

    /// A resume cursor at the target key proves completion without re-emission.
    #[test]
    fn discover_page_cursor_last_key_at_target_returns_none() {
        let target = make_test_target(b"git:repo:c");
        let mut discovery = StaticGitRepoDiscoverySource::new(target.clone());
        let cursor = Cursor::with_last_key(target.repo_key().clone().into_item_key());

        let page = discovery
            .discover_page(&ShardSpec::unbounded(), &cursor, budgets())
            .expect("discover_page succeeds");

        assert!(
            page.is_none(),
            "cursor at target key should complete the source"
        );
    }

    /// The shard lower bound is inclusive when it matches the target key exactly.
    #[test]
    fn discover_page_target_at_shard_start_is_included() {
        let target = make_test_target(b"git:repo:d");
        let mut discovery = StaticGitRepoDiscoverySource::new(target.clone());
        let shard = ShardSpec::with_range(
            target.repo_key().as_bytes(),
            successor_bytes(target.repo_key().as_bytes()),
        );

        let page = discovery
            .discover_page(&shard, &Cursor::initial(), budgets())
            .expect("discover_page succeeds")
            .expect("target should remain in shard");

        assert_eq!(&page.items()[0], &target);
    }

    /// Emitted pages satisfy the shared page-sequence validation contract.
    #[test]
    fn discover_page_emitted_page_passes_validation() {
        let target = make_test_target(b"git:repo:e");
        let mut discovery = StaticGitRepoDiscoverySource::new(target);
        let shard = ShardSpec::unbounded();
        let previous_last = RepoKey::try_from_slice(b"git:repo:d").expect("previous key");

        let page = discovery
            .discover_page(&shard, &Cursor::initial(), budgets())
            .expect("discover_page succeeds")
            .expect("target should emit");

        validate_page_sequence(
            page.items(),
            page.state(),
            Some(previous_last.as_item_key()),
            shard.key_range_start(),
            shard.key_range_end(),
        )
        .expect("page should satisfy shared sequence validation");
    }

    /// One-target sources never expose an interior split point.
    #[test]
    fn choose_split_point_returns_none() {
        let target = make_test_target(b"git:repo:f");
        let mut discovery = StaticGitRepoDiscoverySource::new(target);

        let split = discovery
            .choose_split_point(&ShardSpec::unbounded(), &Cursor::initial(), budgets())
            .expect("choose_split_point succeeds");

        assert_eq!(split, None);
    }

    /// The advertised capabilities match the static one-target discovery contract.
    #[test]
    fn capabilities_reports_ordered_keys_not_resumable_not_splittable() {
        let discovery = StaticGitRepoDiscoverySource::new(make_test_target(b"git:repo:g"));
        let capabilities = discovery.capabilities();

        assert!(capabilities.paging.ordered_keys);
        assert!(!capabilities.paging.resumable);
        assert!(!capabilities.paging.splittable);
    }

    /// The source remains `Send` and trait-compatible for runtime dispatch.
    #[test]
    fn static_source_is_send() {
        fn assert_send<T: Send + GitRepoDiscoverySource>() {}

        assert_send::<StaticGitRepoDiscoverySource>();
    }

    /// Any cursor strictly past the target key completes the source without re-emission.
    #[rstest]
    #[case::key_only(None)]
    #[case::with_token(Some(b"resume-token" as &'static [u8]))]
    fn discover_page_cursor_past_target_returns_none(#[case] token_bytes: Option<&'static [u8]>) {
        let target = make_test_target(b"git:repo:h");
        let mut discovery = StaticGitRepoDiscoverySource::new(target.clone());
        let past_key = RepoKey::try_from_vec(successor_bytes(target.repo_key().as_bytes()))
            .expect("past key")
            .into_item_key();
        let cursor = match token_bytes {
            Some(bytes) => Cursor::with_token(past_key, token(bytes)),
            None => Cursor::with_last_key(past_key),
        };

        let page = discovery
            .discover_page(&ShardSpec::unbounded(), &cursor, budgets())
            .expect("discover_page succeeds");

        assert!(
            page.is_none(),
            "past-key cursor should not re-emit the target"
        );
    }

    /// Opaque tokens do not change key-authoritative resume when the cursor still trails the target.
    #[rstest]
    #[case::no_token(None)]
    #[case::stale_token(Some(b"stale-token" as &'static [u8]))]
    #[case::corrupt_token(Some(&[0_u8, 0xff, 0x01] as &'static [u8]))]
    fn discover_page_corrupt_token_falls_back_to_key(#[case] token_bytes: Option<&'static [u8]>) {
        let target = make_test_target(b"git:repo:i");
        let mut discovery = StaticGitRepoDiscoverySource::new(target.clone());
        let trailing_key = RepoKey::try_from_slice(b"git:repo:").expect("trailing key");
        let cursor = match token_bytes {
            Some(bytes) => Cursor::with_token(trailing_key.into_item_key(), token(bytes)),
            None => Cursor::with_last_key(trailing_key.into_item_key()),
        };

        let page = discovery
            .discover_page(&ShardSpec::unbounded(), &cursor, budgets())
            .expect("discover_page succeeds")
            .expect("key-authoritative resume should still emit");

        assert_eq!(&page.items()[0], &target);
    }

    /// Shard mismatch does not consume the emit-once budget; a subsequent in-range
    /// call on the same source still emits the target.
    #[test]
    fn discover_page_shard_mismatch_does_not_consume_emit_budget() {
        let target = make_test_target(b"git:repo:j");
        let mut discovery = StaticGitRepoDiscoverySource::new(target.clone());

        let excluding_shard = ShardSpec::with_range(b"git:repo:z", vec![]);
        let excluded = discovery
            .discover_page(&excluding_shard, &Cursor::initial(), budgets())
            .expect("discover_page succeeds");
        assert!(excluded.is_none(), "out-of-range target must not emit");

        let page = discovery
            .discover_page(&ShardSpec::unbounded(), &Cursor::initial(), budgets())
            .expect("discover_page succeeds")
            .expect("re-emission should succeed after shard mismatch");

        assert_eq!(&page.items()[0], &target);
    }

    /// A covering cursor returns `Ok(None)` without consuming the emit budget,
    /// so the source remains reusable after a cursor reset.
    #[test]
    fn discover_page_covering_cursor_does_not_consume_emit_budget() {
        let target = make_test_target(b"git:repo:k");
        let mut discovery = StaticGitRepoDiscoverySource::new(target.clone());
        let covering = Cursor::with_last_key(target.repo_key().clone().into_item_key());

        let covered = discovery
            .discover_page(&ShardSpec::unbounded(), &covering, budgets())
            .expect("discover_page succeeds");
        assert!(covered.is_none(), "covering cursor completes the source");

        let page = discovery
            .discover_page(&ShardSpec::unbounded(), &Cursor::initial(), budgets())
            .expect("discover_page succeeds")
            .expect("source should remain reusable after cursor reset");

        assert_eq!(&page.items()[0], &target);
    }

    /// Targets outside `[start, end)` are never emitted for the current shard.
    #[rstest]
    #[case::below_start(
        b"git:repo:g" as &[u8],
        ShardSpec::with_range(b"git:repo:h", vec![]),
    )]
    #[case::equal_end(
        b"git:repo:m" as &[u8],
        ShardSpec::with_range(vec![], b"git:repo:m"),
    )]
    #[case::above_end(
        b"git:repo:z" as &[u8],
        ShardSpec::with_range(vec![], b"git:repo:m"),
    )]
    fn discover_page_shard_excludes_target_key(
        #[case] target_bytes: &[u8],
        #[case] shard: ShardSpec,
    ) {
        let mut discovery = StaticGitRepoDiscoverySource::new(make_test_target(target_bytes));

        let page = discovery
            .discover_page(&shard, &Cursor::initial(), budgets())
            .expect("discover_page succeeds");

        assert!(page.is_none(), "out-of-range target must not emit");
    }

    proptest! {
        /// Discovery emits exactly when the carried key falls within `[start, end)`.
        #[test]
        fn discover_page_proptest_key_and_shard_bounds(
            key_bytes in proptest::collection::vec(any::<u8>(), 1..32),
            relation in 0_u8..4,
        ) {
            let target = make_test_target(&key_bytes);
            let mut discovery = StaticGitRepoDiscoverySource::new(target);
            let (shard, should_emit) = match relation {
                0 => (ShardSpec::unbounded(), true),
                1 => (
                    ShardSpec::with_range(key_bytes.clone(), successor_bytes(&key_bytes)),
                    true,
                ),
                2 => (
                    ShardSpec::with_range(successor_bytes(&key_bytes), vec![]),
                    false,
                ),
                _ => (
                    ShardSpec::with_range(vec![], key_bytes.clone()),
                    false,
                ),
            };

            let page = discovery
                .discover_page(&shard, &Cursor::initial(), budgets())
                .expect("discover_page succeeds");

            if should_emit {
                let page = page.expect("target should emit");
                prop_assert_eq!(page.state(), &PageState::Complete);
                validate_filled_page(
                    page.items(),
                    shard.key_range_start(),
                    shard.key_range_end(),
                ).expect("emitted page should validate");
            } else {
                prop_assert!(page.is_none());
            }
        }
    }

    proptest! {
        /// A cursor at the emitted key makes a fresh source replay-safe and idempotent.
        #[test]
        fn discover_page_proptest_resume_idempotence(
            key_bytes in proptest::collection::vec(any::<u8>(), 1..32),
        ) {
            let target = make_test_target(&key_bytes);
            let shard = ShardSpec::unbounded();

            let first_page = StaticGitRepoDiscoverySource::new(target.clone())
                .discover_page(&shard, &Cursor::initial(), budgets())
                .expect("discover_page succeeds");
            prop_assert!(first_page.is_some(), "initial discovery should emit");

            let resume_cursor = Cursor::with_last_key(target.repo_key().clone().into_item_key());
            let resumed = StaticGitRepoDiscoverySource::new(target)
                .discover_page(&shard, &resume_cursor, budgets())
                .expect("resume discovery succeeds");

            prop_assert!(resumed.is_none(), "resume cursor at emitted key must complete the source");
        }
    }
}
