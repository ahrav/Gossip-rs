//! Property tests for tree diff walker.
//!
//! These tests synthesize Git tree payloads from generated path sets, then
//! validate that the walker emits the same changes as a straightforward
//! reference map. Tree objects are encoded in canonical Git order using
//! `git_tree_name_cmp`, and OIDs are deterministic but synthetic (Blake3
//! truncated to 20 bytes) so we can compare structure without invoking `git`.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::AtomicBool;

use proptest::prelude::*;

use scanner_git::{
    CandidateBuffer, ChangeKind, OidBytes, TreeBytes, TreeDiffError, TreeDiffLimits,
    TreeDiffWalker, TreeSource, git_tree_name_cmp,
};

static NEVER_ABORT: AtomicBool = AtomicBool::new(false);

/// In-memory tree store keyed by synthetic OIDs.
#[derive(Default)]
struct TestTreeStore {
    trees: HashMap<OidBytes, Vec<u8>>,
}

impl TreeSource for TestTreeStore {
    fn load_tree(&mut self, oid: &OidBytes) -> Result<TreeBytes, TreeDiffError> {
        self.trees
            .get(oid)
            .cloned()
            .map(TreeBytes::Owned)
            .ok_or(TreeDiffError::TreeNotFound)
    }
}

/// Minimal directory tree used to build raw tree payloads.
#[derive(Default)]
struct Node {
    files: Vec<(Vec<u8>, OidBytes)>,
    dirs: BTreeMap<Vec<u8>, Node>,
}

/// Insert a file path into the directory tree, creating intermediate dirs.
///
/// Paths are expected to be slash-delimited and unique (the generator uses a
/// `BTreeSet`), so this does not attempt to resolve duplicates.
fn insert_path(node: &mut Node, path: &[u8], oid: OidBytes) {
    if let Some(pos) = path.iter().position(|&b| b == b'/') {
        let (dir, rest) = path.split_at(pos);
        let rest = &rest[1..];
        let child = node.dirs.entry(dir.to_vec()).or_default();
        insert_path(child, rest, oid);
    } else {
        node.files.push((path.to_vec(), oid));
    }
}

/// Build a raw tree payload for `node`, store it, and return its synthetic OID.
///
/// The payload matches Git's tree entry format and is sorted using Git's
/// tree ordering rules so traversal logic sees canonical ordering.
fn build_tree(node: &Node, store: &mut HashMap<OidBytes, Vec<u8>>) -> OidBytes {
    struct Entry {
        name: Vec<u8>,
        is_tree: bool,
        mode: &'static [u8],
        oid: OidBytes,
    }

    let mut entries: Vec<Entry> = Vec::new();
    for (name, oid) in &node.files {
        entries.push(Entry {
            name: name.clone(),
            is_tree: false,
            mode: b"100644",
            oid: *oid,
        });
    }

    for (name, child) in &node.dirs {
        let child_oid = build_tree(child, store);
        entries.push(Entry {
            name: name.clone(),
            is_tree: true,
            mode: b"40000",
            oid: child_oid,
        });
    }

    entries.sort_by(|a, b| git_tree_name_cmp(&a.name, a.is_tree, &b.name, b.is_tree));

    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend_from_slice(entry.mode);
        bytes.push(b' ');
        bytes.extend_from_slice(&entry.name);
        bytes.push(0);
        bytes.extend_from_slice(entry.oid.as_slice());
    }

    // Use a deterministic hash so we can refer to trees without implementing
    // Git's object hashing in tests.
    let hash = blake3::hash(&bytes);
    let mut oid_bytes = [0u8; 20];
    oid_bytes.copy_from_slice(&hash.as_bytes()[..20]);
    let oid = OidBytes::sha1(oid_bytes);

    store.insert(oid, bytes);
    oid
}

/// Build a root tree from a list of `(path, oid)` entries.
///
/// Returns the root OID (or `None` for an empty tree) plus the populated
/// object store backing the tree structure.
fn build_root(paths: &[(Vec<u8>, OidBytes)]) -> (Option<OidBytes>, HashMap<OidBytes, Vec<u8>>) {
    if paths.is_empty() {
        return (None, HashMap::new());
    }

    let mut root = Node::default();
    for (path, oid) in paths {
        insert_path(&mut root, path, *oid);
    }

    let mut store = HashMap::new();
    let root_oid = build_tree(&root, &mut store);
    (Some(root_oid), store)
}

/// Run a tree diff and collect results into an ordered map for comparisons.
fn collect_candidates_map(
    source: &mut TestTreeStore,
    limits: &TreeDiffLimits,
    new_root: Option<&OidBytes>,
    old_root: Option<&OidBytes>,
) -> BTreeMap<Vec<u8>, (ChangeKind, OidBytes)> {
    let mut walker = TreeDiffWalker::new(limits, 20);
    let mut candidates = CandidateBuffer::new(limits, 20);

    walker
        .diff_trees(
            source,
            &mut candidates,
            new_root,
            old_root,
            0,
            0,
            &NEVER_ABORT,
        )
        .unwrap();

    let mut out = BTreeMap::new();
    for cand in candidates.iter_resolved() {
        out.insert(cand.path.to_vec(), (cand.change_kind, cand.oid));
    }
    out
}

/// Create a synthetic SHA-1 OID filled with a single byte value.
fn oid_from_byte(val: u8) -> OidBytes {
    OidBytes::sha1([val; 20])
}

/// Generate short, slash-delimited ASCII paths.
fn path_strategy() -> impl Strategy<Value = Vec<u8>> {
    let seg = prop::string::string_regex("[a-z]{1,6}").unwrap();
    prop::collection::vec(seg, 1..=3).prop_map(|parts| parts.join("/").into_bytes())
}

proptest! {
    #[test]
    fn diff_matches_reference(
        (paths, flags) in prop::collection::btree_set(path_strategy(), 0..=12)
            .prop_flat_map(|paths| {
                let len = paths.len();
                (
                    Just(paths),
                    prop::collection::vec(
                        (any::<bool>(), any::<bool>(), any::<u8>(), any::<u8>(), any::<bool>()),
                        len,
                    ),
                )
            }),
    ) {
        let path_vec: Vec<Vec<u8>> = paths.into_iter().collect();
        let mut old_entries: Vec<(Vec<u8>, OidBytes)> = Vec::new();
        let mut new_entries: Vec<(Vec<u8>, OidBytes)> = Vec::new();

        for (path, (in_old, in_new, old_val, new_val, same)) in path_vec.iter().zip(flags) {
            let old_oid = oid_from_byte(old_val);
            let mut new_oid = oid_from_byte(new_val);

            if in_old {
                old_entries.push((path.clone(), old_oid));
            }
            if in_new {
                // Ensure we can force a stable or changed OID without accidental collisions.
                if in_old && same {
                    new_oid = old_oid;
                } else if in_old && new_oid == old_oid {
                    new_oid = oid_from_byte(old_val.wrapping_add(1));
                }
                new_entries.push((path.clone(), new_oid));
            }
        }

        let (old_root, mut store) = build_root(&old_entries);
        let (new_root, new_store) = build_root(&new_entries);
        store.extend(new_store);

        let mut source = TestTreeStore { trees: store };

        let limits = TreeDiffLimits {
            max_candidates: (path_vec.len() as u32).saturating_add(32),
            max_path_arena_bytes: 1024 * 1024,
            max_tree_bytes_in_flight: 4 * 1024 * 1024,
            max_tree_spill_bytes: 4 * 1024 * 1024,
            max_tree_cache_bytes: 2 * 1024 * 1024,
            max_tree_delta_cache_bytes: 2 * 1024 * 1024,
            max_tree_depth: 64,
        };

        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                new_root.as_ref(),
                old_root.as_ref(),
                0,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        // Reference diff: map old and new entries and compare by path.
        let mut expected: BTreeMap<Vec<u8>, (ChangeKind, OidBytes)> = BTreeMap::new();
        let mut old_map: BTreeMap<Vec<u8>, OidBytes> = BTreeMap::new();
        for (path, oid) in &old_entries {
            old_map.insert(path.clone(), *oid);
        }

        for (path, oid) in &new_entries {
            match old_map.get(path) {
                None => {
                    expected.insert(path.clone(), (ChangeKind::Add, *oid));
                }
                Some(old_oid) if old_oid != oid => {
                    expected.insert(path.clone(), (ChangeKind::Modify, *oid));
                }
                _ => {}
            }
        }

        let mut actual: BTreeMap<Vec<u8>, (ChangeKind, OidBytes)> = BTreeMap::new();
        for cand in candidates.iter_resolved() {
            actual.insert(cand.path.to_vec(), (cand.change_kind, cand.oid));
        }

        prop_assert_eq!(actual, expected);
    }
}

proptest! {
    #[test]
    fn streaming_matches_buffered(
        (paths, flags) in prop::collection::btree_set(path_strategy(), 0..=12)
            .prop_flat_map(|paths| {
                let len = paths.len();
                (
                    Just(paths),
                    prop::collection::vec(
                        (any::<bool>(), any::<bool>(), any::<u8>(), any::<u8>(), any::<bool>()),
                        len,
                    ),
                )
            }),
    ) {
        let path_vec: Vec<Vec<u8>> = paths.into_iter().collect();
        let mut old_entries: Vec<(Vec<u8>, OidBytes)> = Vec::new();
        let mut new_entries: Vec<(Vec<u8>, OidBytes)> = Vec::new();

        for (path, (in_old, in_new, old_val, new_val, same)) in path_vec.iter().zip(flags) {
            let old_oid = oid_from_byte(old_val);
            let mut new_oid = oid_from_byte(new_val);

            if in_old {
                old_entries.push((path.clone(), old_oid));
            }
            if in_new {
                if in_old && same {
                    new_oid = old_oid;
                } else if in_old && new_oid == old_oid {
                    new_oid = oid_from_byte(old_val.wrapping_add(1));
                }
                new_entries.push((path.clone(), new_oid));
            }
        }

        let (old_root, mut store) = build_root(&old_entries);
        let (new_root, new_store) = build_root(&new_entries);
        store.extend(new_store);

        let mut source_stream = TestTreeStore { trees: store.clone() };
        let mut source_buffered = TestTreeStore { trees: store };

        // Streaming limits: tiny cache/spill budget so the walker must
        // re-load tree payloads instead of relying on the cache.
        let limits_stream = TreeDiffLimits {
            max_candidates: (path_vec.len() as u32).saturating_add(32),
            max_path_arena_bytes: 1024 * 1024,
            max_tree_bytes_in_flight: 4 * 1024 * 1024,
            max_tree_spill_bytes: 1,
            max_tree_cache_bytes: 64,
            max_tree_delta_cache_bytes: 64,
            max_tree_depth: 64,
        };

        // Buffered limits: large cache and spill budget to maximize reuse.
        let mut limits_buffered = limits_stream;
        limits_buffered.max_tree_cache_bytes = 2 * 1024 * 1024;
        limits_buffered.max_tree_spill_bytes = 2 * 1024 * 1024;

        let stream_out = collect_candidates_map(
            &mut source_stream,
            &limits_stream,
            new_root.as_ref(),
            old_root.as_ref(),
        );
        let buffered_out = collect_candidates_map(
            &mut source_buffered,
            &limits_buffered,
            new_root.as_ref(),
            old_root.as_ref(),
        );

        prop_assert_eq!(stream_out, buffered_out);
    }
}
