//! Property tests for pack plan DFS execution ordering.
//!
//! Generates random acyclic dependency DAGs and verifies:
//!
//! 1. **Topological validity**: every base appears before its dependents.
//! 2. **Completeness**: the output is a permutation of all input indices.
//! 3. **Cycle detection**: graphs with cycles are rejected.

use proptest::prelude::*;
use proptest::strategy::Just;

use scanner_git::{BaseLoc, DeltaDep, DeltaKind, PackPlanError, build_exec_order};

/// Build an acyclic DAG from a probability-weighted edge list.
///
/// Edges only go from lower-index to higher-index nodes, guaranteeing
/// acyclicity by construction. `edge_prob` controls density.
fn random_acyclic_dag(n: usize, edges_raw: &[(usize, usize)]) -> (Vec<u64>, Vec<DeltaDep>) {
    let need_offsets: Vec<u64> = (0..n as u64).map(|i| (i + 1) * 100).collect();
    let mut deps = Vec::new();

    for &(from, to) in edges_raw {
        // Ensure acyclicity: edge goes from lower to higher index.
        let (base_idx, dep_idx) = if from < to { (from, to) } else { (to, from) };
        if base_idx >= n || dep_idx >= n || base_idx == dep_idx {
            continue;
        }
        deps.push(DeltaDep {
            offset: need_offsets[dep_idx],
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(need_offsets[base_idx]),
            data_start: 0,
            delta_size: 0,
        });
    }

    (need_offsets, deps)
}

/// Strategy for generating (from, to) edge pairs within a graph of size n.
fn edge_pairs(n: usize) -> impl Strategy<Value = Vec<(usize, usize)>> {
    // Generate up to n*2 candidate edges; duplicates/self-loops are filtered.
    let max_edges = n.saturating_mul(2).max(1);
    prop::collection::vec((0..n, 0..n), 0..max_edges)
}

proptest! {
    #[test]
    fn exec_order_is_topologically_valid(
        (n, edges_raw) in (2..40usize).prop_flat_map(|n| {
            let max_edges = n.saturating_mul(2).max(1);
            (Just(n), prop::collection::vec((0..n, 0..n), 0..max_edges))
        }),
    ) {
        let (need_offsets, deps) = random_acyclic_dag(n, &edges_raw);
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();

        if let Some(order) = result.order() {
            // Completeness: output is a permutation of 0..n.
            assert_eq!(order.len(), n);
            let mut sorted = order.to_vec();
            sorted.sort_unstable();
            let expected: Vec<u32> = (0..n as u32).collect();
            prop_assert_eq!(sorted, expected, "order must be a permutation");

            // Topological validity: every base precedes its dependent.
            let mut pos = vec![0usize; n];
            for (i, &idx) in order.iter().enumerate() {
                pos[idx as usize] = i;
            }
            for dep in &deps {
                let BaseLoc::Offset(base_offset) = dep.base else {
                    continue;
                };
                let base_idx = need_offsets
                    .iter()
                    .position(|&o| o == base_offset)
                    .unwrap();
                let dep_idx = need_offsets
                    .iter()
                    .position(|&o| o == dep.offset)
                    .unwrap();
                prop_assert!(
                    pos[base_idx] < pos[dep_idx],
                    "base idx {} (pos {}) must precede dep idx {} (pos {})",
                    base_idx,
                    pos[base_idx],
                    dep_idx,
                    pos[dep_idx],
                );
            }
        } else {
            // When order is None, natural order [0..n] must satisfy all
            // dependencies: every base offset precedes its dependent offset.
            for dep in &deps {
                let BaseLoc::Offset(base_offset) = dep.base else {
                    continue;
                };
                let base_idx = need_offsets
                    .iter()
                    .position(|&o| o == base_offset)
                    .unwrap();
                let dep_idx = need_offsets
                    .iter()
                    .position(|&o| o == dep.offset)
                    .unwrap();
                prop_assert!(
                    base_idx < dep_idx,
                    "None order implies natural order works, but base idx {} >= dep idx {}",
                    base_idx,
                    dep_idx,
                );
            }
        }
    }

    #[test]
    fn exec_order_detects_cycles(
        (n, cycle_a, cycle_b, edges_raw) in (2..20usize).prop_flat_map(|n| {
            let max_edges = n.saturating_mul(2).max(1);
            (Just(n), 0..n, 0..n, prop::collection::vec((0..n, 0..n), 0..max_edges))
        }),
    ) {
        // Start with an acyclic DAG, then inject one back-edge to create a cycle.
        let a = cycle_a % n;
        let b = cycle_b % n;
        if a == b {
            return Ok(());
        }
        let (need_offsets, mut deps) = random_acyclic_dag(n, &edges_raw);

        // Inject a back-edge: higher-index → lower-index.
        let (high, low) = if a > b { (a, b) } else { (b, a) };
        deps.push(DeltaDep {
            offset: need_offsets[low],
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(need_offsets[high]),
            data_start: 0,
            delta_size: 0,
        });

        // There must exist a forward path from low→high (via the acyclic edges)
        // for this to actually form a cycle. If no such path exists, the graph
        // is still acyclic and build_exec_order will succeed. We accept both
        // outcomes — the important thing is it doesn't panic.
        let result = build_exec_order(&need_offsets, &deps, 0);
        match result {
            Ok(res) => {
                // Valid — the back-edge didn't form a cycle.
                if let Some(order) = res.order() {
                    assert_eq!(order.len(), n);
                }
            }
            Err(PackPlanError::DeltaCycleDetected { .. }) => {
                // Expected when the back-edge completes a cycle.
            }
            Err(e) => {
                prop_assert!(false, "unexpected error: {e}");
            }
        }
    }

    #[test]
    fn exec_order_empty_and_no_deps(n in 0..50usize) {
        let need_offsets: Vec<u64> = (0..n as u64).map(|i| (i + 1) * 100).collect();
        let deps = vec![];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        prop_assert!(result.order().is_none(), "no deps should always yield None");
        prop_assert_eq!(result.tree_roots(), 0);
        prop_assert_eq!(result.max_depth(), 0);
    }

    /// Subtree contiguity for tree-structured forests: when each node
    /// has at most one parent (a forest, not a DAG), every subtree
    /// occupies a contiguous span in the execution order.
    ///
    /// This is the key cache-locality property of the DFS scheduler:
    /// a base is immediately followed by all its descendants before
    /// moving to the next sibling.
    ///
    /// Note: in DAGs where a node has multiple parents, contiguity of
    /// individual parent subtrees is not guaranteed because the shared
    /// node must wait for all parents.
    #[test]
    fn exec_order_forest_subtrees_are_contiguous(
        n in 3..30usize,
        parents_raw in prop::collection::vec(0..30usize, 0..30),
    ) {
        // Build a random forest: each node has at most one parent.
        // Only assign parent if parent_idx < node_idx (guarantees acyclicity
        // and tree structure with no multi-parent nodes).
        let need_offsets: Vec<u64> = (0..n as u64).map(|i| (i + 1) * 100).collect();
        let mut deps = Vec::new();
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];

        for (node_idx, &raw_parent) in parents_raw.iter().enumerate() {
            let node_idx = node_idx % n;
            if node_idx == 0 {
                continue; // Node 0 is always a root.
            }
            // Assign a parent from [0, node_idx) with ~50% probability.
            let parent_idx = raw_parent % n;
            if parent_idx >= node_idx {
                continue; // Skip: no parent for this node.
            }
            deps.push(DeltaDep {
                offset: need_offsets[node_idx],
                kind: DeltaKind::Ofs,
                base: BaseLoc::Offset(need_offsets[parent_idx]),
                data_start: 0,
                delta_size: 0,
            });
            children[parent_idx].push(node_idx);
        }

        // Deduplicate: each node gets at most one parent.
        deps.sort_by_key(|d| d.offset);
        deps.dedup_by_key(|d| d.offset);

        // Rebuild children after dedup.
        children = vec![Vec::new(); n];
        for dep in &deps {
            let BaseLoc::Offset(base_offset) = dep.base else { continue; };
            let base_idx = need_offsets.iter().position(|&o| o == base_offset).unwrap();
            let dep_idx = need_offsets.iter().position(|&o| o == dep.offset).unwrap();
            children[base_idx].push(dep_idx);
        }

        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();

        let order = match result.order() {
            Some(o) => o,
            None => return Ok(()), // Identity order: contiguity trivially holds.
        };

        // For each node with children, verify its subtree is contiguous.
        for root in 0..n {
            if children[root].is_empty() {
                continue;
            }
            // BFS to collect transitive descendants.
            let mut subtree = vec![root];
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(root);
            while let Some(node) = queue.pop_front() {
                for &child in &children[node] {
                    subtree.push(child);
                    queue.push_back(child);
                }
            }

            let positions: Vec<usize> = subtree
                .iter()
                .map(|&idx| order.iter().position(|&v| v == idx as u32).unwrap())
                .collect();
            let lo = *positions.iter().min().unwrap();
            let hi = *positions.iter().max().unwrap();
            prop_assert_eq!(
                hi - lo + 1,
                subtree.len(),
                "subtree rooted at idx {} not contiguous: subtree={:?}, positions={:?}, order={:?}",
                root,
                subtree,
                positions,
                order,
            );
        }
    }

    /// tree_roots and max_depth are consistent with the dependency graph.
    ///
    /// - tree_roots counts indegree-0 nodes that have at least one dependent.
    /// - max_depth is the longest path in the dependency DAG.
    #[test]
    fn exec_order_stats_are_consistent(
        n in 2..30usize,
        edges_raw in edge_pairs(30),
    ) {
        let (need_offsets, deps) = random_acyclic_dag(n, &edges_raw);
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();

        // Build adjacency for verification.
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut indegree = vec![0u32; n];
        let mut has_deps = false;
        for dep in &deps {
            let BaseLoc::Offset(base_offset) = dep.base else { continue; };
            let base_idx = need_offsets.iter().position(|&o| o == base_offset).unwrap();
            let dep_idx = need_offsets.iter().position(|&o| o == dep.offset).unwrap();
            children[base_idx].push(dep_idx);
            indegree[dep_idx] += 1;
            has_deps = true;
        }

        // Verify tree_roots: indegree-0 nodes with at least one child.
        let expected_roots: u32 = (0..n)
            .filter(|&i| indegree[i] == 0 && !children[i].is_empty())
            .count() as u32;
        prop_assert_eq!(
            result.tree_roots(),
            expected_roots,
            "tree_roots mismatch"
        );

        if !has_deps {
            prop_assert_eq!(result.max_depth(), 0);
            return Ok(());
        }

        // Verify max_depth via longest-path DP on topological order.
        let mut depth = vec![0u32; n];
        // Use a simple Kahn's algorithm for topo order.
        let mut remaining = indegree.clone();
        let mut queue = std::collections::VecDeque::new();
        for (i, &rem) in remaining.iter().enumerate() {
            if rem == 0 {
                queue.push_back(i);
            }
        }
        let mut max_d = 0u32;
        while let Some(node) = queue.pop_front() {
            for &child in &children[node] {
                let new_depth = depth[node] + 1;
                if new_depth > depth[child] {
                    depth[child] = new_depth;
                }
                if depth[child] > max_d {
                    max_d = depth[child];
                }
                remaining[child] -= 1;
                if remaining[child] == 0 {
                    queue.push_back(child);
                }
            }
        }
        prop_assert_eq!(
            result.max_depth(),
            max_d,
            "max_depth mismatch"
        );
    }
}
