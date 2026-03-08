# Cursor Resume Strategy

This document details the two-layer cursor architecture used by the **B4 Connector**
boundary for paginated enumeration and fault-tolerant resume. Every connector must
produce globally sorted item keys and advance a `Cursor` that allows the coordination
layer to resume enumeration from an arbitrary checkpoint. The cursor carries both a
key-authoritative progress marker and an optional connector-opaque token that enables
O(1) position restoration when the token is valid.

The key insight is a **safety-first, speed-second** design: the `last_key` field
guarantees correct resume under any conditions (token loss, corruption, connector
restart, filesystem mutation), while the optional `token` field accelerates the common
case by allowing connectors to skip binary search or DFS traversal when the token is
still valid.

All diagrams use the B4 Connector color palette (fill `#EF4444` / `#FEE2E2`, stroke
`#991B1B`). Cross-boundary references use the corresponding boundary colors from the
[color legend](00-README.md#color-coding-legend).

---

## 1. Two-Layer Cursor Architecture

The `Cursor` struct encodes enumeration progress in two complementary layers. The
`last_key` field (an `ItemKey`) records the lexicographically greatest key that has
been fully processed. This field is **always present** after the first page and is
the authoritative resume position — the coordination layer uses it for cursor
monotonicity enforcement, and connectors use it as the fallback resume anchor.

The `token` field (an `Option<TokenBytes>`) carries connector-specific opaque state
that can restore enumeration position in O(1) time. Connectors that support tokens
encode internal state (DFS stack positions, sorted-index offsets) into this field.
Token content is opaque to the coordination layer; it is round-tripped verbatim
between `enumerate_page` calls.

The `Cursor` type makes the invalid state `(None, Some(token))` — a token without
a progress key — unrepresentable. All constructors enforce this invariant, and
`try_from_update` rejects it when crossing the coordination boundary.

```mermaid
%% Diagram: two-layer-cursor-architecture
graph TD
    subgraph cursor_type["Cursor (gossip-contracts)"]
        LK["<b>last_key: Option&lt;ItemKey&gt;</b><br/>Ordered progress marker<br/>Lexicographic comparison"]
        TK["<b>token: Option&lt;TokenBytes&gt;</b><br/>Connector-opaque resume state<br/>Max 16 KiB, round-tripped verbatim"]
    end

    subgraph constructors["Cursor Constructors"]
        CI["<b>Cursor::initial()</b><br/>last_key: None<br/>token: None"]
        CK["<b>Cursor::with_last_key(key)</b><br/>last_key: Some(key)<br/>token: None"]
        CT["<b>Cursor::with_token(key, tok)</b><br/>last_key: Some(key)<br/>token: Some(tok)"]
        INVALID["<b>INVALID STATE</b><br/>last_key: None<br/>token: Some(_)<br/>← unrepresentable"]
    end

    subgraph states["Cursor Lifecycle"]
        S0["<b>Initial</b><br/>No prior progress<br/>Start from shard beginning"]
        S1["<b>Key-Only</b><br/>last_key present<br/>Resume via binary search /<br/>DFS walk + seek"]
        S2["<b>Key + Token</b><br/>Both fields present<br/>O(1) resume when token valid,<br/>key fallback otherwise"]
    end

    CI --> S0
    CK --> S1
    CT --> S2

    S0 -->|"first page returns items"| S1
    S0 -->|"first page returns items<br/>(token-capable connector)"| S2
    S1 -->|"connector emits token"| S2
    S2 -->|"token lost or corrupt"| S1
    S2 -->|"next page continues"| S2

    TK -.->|"always paired with"| LK

    style cursor_type fill:none,stroke:#991B1B,stroke-width:1px
    style constructors fill:none,stroke:#991B1B,stroke-width:1px
    style states fill:none,stroke:#991B1B,stroke-width:1px

    style LK fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style TK fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style CI fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style CK fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style CT fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style INVALID fill:#F3F4F6,stroke:#374151,stroke-width:2px,stroke-dasharray:5 5,color:#374151
    style S0 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style S1 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style S2 fill:#EF4444,stroke:#991B1B,stroke-width:2px,color:#FFFFFF
```

---

## 2. Resume Decision Tree

When `enumerate_page()` receives a cursor, every connector follows the same logical
decision tree to determine where to begin emitting items. The two resume paths —
token-assisted (O(1)) and key-based (O(log N) or O(N)) — are **semantically
equivalent**: both must resume from the first item strictly greater than
`cursor.last_key()`. The token path is a performance optimization, not a correctness
requirement.

Key-based resume uses `key_resume_start()`, which performs an O(log N)
`upper_bound` binary search on sorted entries (git, in-memory connectors) or an
O(N) DFS walk-and-skip from root (filesystem connector).

Token-assisted resume decodes the token and attempts to restore position directly.
For index-based connectors (git, in-memory), this is an O(1) array index lookup
cross-checked against the last emitted key. For the filesystem connector, this
reconstructs the DFS stack from a serialized walk checkpoint, then seeks forward
from the restored position.

The token can only **advance** the resume position forward, never behind the
key-derived floor — this is enforced by `start_idx = start_idx.max(token_idx)`.

```mermaid
%% Diagram: resume-decision-tree
flowchart TD
    START(["enumerate_page(shard, cursor, budgets)"])
    Q1{"cursor.last_key()<br/>is None?"}
    Q2{"cursor.token()<br/>is Some?"}
    Q3{"Token decode +<br/>restore succeeds?"}
    Q4{"Cross-check:<br/>entry at token_idx − 1<br/>matches last_key?"}

    A1["Start from shard beginning<br/>(range_start index)"]
    A2["Key-based resume<br/>upper_bound(last_key)<br/>O(log N) binary search /<br/>O(N) DFS walk + seek"]
    A3["Token-assisted resume<br/>O(1) index lookup /<br/>DFS stack restore"]

    MERGE["start_idx = max(key_resume, token_resume)<br/>Token can only advance, never retreat"]
    EMIT["Emit items from start_idx<br/>within shard [start, end) range"]

    START --> Q1
    Q1 -->|"Yes"| A1
    Q1 -->|"No"| Q2
    Q2 -->|"No"| A2
    Q2 -->|"Yes"| Q3
    Q3 -->|"No (malformed,<br/>out of range)"| A2
    Q3 -->|"Yes"| Q4
    Q4 -->|"No (stale token,<br/>snapshot drift)"| A2
    Q4 -->|"Yes"| A3

    A1 --> EMIT
    A2 --> EMIT
    A3 --> MERGE
    MERGE --> EMIT

    style START fill:#EF4444,stroke:#991B1B,stroke-width:2px,color:#FFFFFF
    style Q1 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style Q2 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style Q3 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style Q4 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style A1 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style A2 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style A3 fill:#EF4444,stroke:#991B1B,stroke-width:2px,color:#FFFFFF
    style MERGE fill:#EF4444,stroke:#991B1B,stroke-width:2px,color:#FFFFFF
    style EMIT fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
```

---

## 3. Token Encoding per Connector

Each connector stores different internal state in the `TokenBytes` field. The
coordination layer never interprets token contents — it validates only presence
and size (`MAX_TOKEN_SIZE = 16 KiB`). The three concrete connectors use
fundamentally different encoding strategies matched to their data access patterns.

**FilesystemConnector** encodes a `WalkToken` — a serialized snapshot of the DFS
stack. Each frame records a directory path component and a `next_child_index` (the
count of already-consumed children in that directory's sorted entry list). On
resume, the connector re-reads each directory from disk, re-sorts entries, and
fast-forwards past the consumed children. This restores DFS position without
replaying the entire walk from root. The wire format includes a version byte for
forward compatibility. When the token's frame count exceeds `MAX_TOKEN_SIZE`, deeper
frames are truncated and the leaf frame's index is rewound by one to force
re-descent into the truncated subtree.

**GitConnector** encodes the next absolute index in the sorted entry array as an
8-byte big-endian `u64`. Since the git snapshot is immutable after indexing, the
index is stable for the connector's lifetime. Resume decodes the u64, verifies
`entries[token_idx - 1].key == cursor.last_key()`, and jumps directly to
`entries[token_idx]`.

**InMemoryDeterministicConnector** uses the same 8-byte big-endian `u64` encoding
as the git connector. The sorted `Vec<PreparedItem>` is immutable after
construction, so the index provides the same O(1) guarantee.

```mermaid
%% Diagram: token-encoding-per-connector
graph LR
    subgraph fs_token["FilesystemConnector Token"]
        FS_HDR["version: u8<br/>(0x01)"]
        FS_FC["frame_count: u16 LE"]
        FS_F0["Frame 0 (root):<br/>component: [] (empty)<br/>next_child_index: u32 LE"]
        FS_F1["Frame 1:<br/>component: dir_name bytes<br/>next_child_index: u32 LE"]
        FS_FN["Frame N (leaf):<br/>component: dir_name bytes<br/>next_child_index: u32 LE"]
    end

    subgraph git_token["GitConnector Token"]
        GIT_TOK["8 bytes big-endian u64<br/>= next absolute index<br/>into sorted entry array"]
    end

    subgraph mem_token["InMemoryDeterministicConnector Token"]
        MEM_TOK["8 bytes big-endian u64<br/>= next absolute index<br/>into sorted Vec"]
    end

    subgraph resume_cost["Resume Complexity"]
        FS_COST["Filesystem:<br/>O(depth × entries_per_dir)<br/>Re-read + re-sort + skip"]
        GIT_COST["Git:<br/>O(1) array index<br/>+ key cross-check"]
        MEM_COST["In-Memory:<br/>O(1) array index<br/>+ key cross-check"]
    end

    FS_HDR --> FS_FC --> FS_F0 --> FS_F1 --> FS_FN
    GIT_TOK --> GIT_COST
    MEM_TOK --> MEM_COST
    FS_FN --> FS_COST

    style fs_token fill:none,stroke:#991B1B,stroke-width:1px
    style git_token fill:none,stroke:#991B1B,stroke-width:1px
    style mem_token fill:none,stroke:#991B1B,stroke-width:1px
    style resume_cost fill:none,stroke:#991B1B,stroke-width:1px

    style FS_HDR fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style FS_FC fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style FS_F0 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style FS_F1 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style FS_FN fill:#EF4444,stroke:#991B1B,stroke-width:2px,color:#FFFFFF
    style GIT_TOK fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style MEM_TOK fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style FS_COST fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style GIT_COST fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style MEM_COST fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
```

---

## 4. Token Resilience Model

The conformance harness validates that token loss or corruption never causes data
loss. Every connector must produce semantically identical results regardless of
whether the cursor carries a valid token, no token, or a corrupted token. The
`ResumeChecks` configuration controls two independent perturbation scenarios:

- **Drop token** (`ResumeMode::DropToken`): The harness removes the cursor's
  `token` field entirely, leaving only `last_key`. The connector must resume
  from the key position using binary search or DFS walk-and-seek.

- **Corrupt token** (`ResumeMode::CorruptToken`): The harness replaces the
  cursor's `token` with random bytes. The connector must detect the invalid
  token (wrong version byte, malformed frames, index out of bounds, key
  cross-check failure) and fall back to key-based resume.

Both perturbation paths must produce the same suffix of items as normal
token-assisted resume. This is verified by comparing `ItemObservation` sequences
(BLAKE3 digests of key and fingerprint) element-by-element against the baseline
trace.

```mermaid
%% Diagram: token-resilience-model
sequenceDiagram
    participant H as Conformance Harness
    participant C as Connector

    Note over H,C: Phase 1 — Baseline enumeration

    H->>C: enumerate_page(shard, initial_cursor, budgets)
    C-->>H: page₁ {items, cursor₁ with token}
    H->>C: enumerate_page(shard, cursor₁, budgets)
    C-->>H: page₂ {items, cursor₂ with token}
    Note over H: Record baseline trace:<br/>items + cursor checkpoints

    Note over H,C: Phase 2 — Resume from checkpoint with DROP TOKEN

    H->>H: cursor₁' = Cursor::with_last_key(cursor₁.last_key)<br/>← token removed
    H->>C: enumerate_page(shard, cursor₁', budgets)
    Note over C: No token → key_resume_start()<br/>upper_bound(last_key) O(log N)
    C-->>H: page₂' {items must match baseline suffix}

    Note over H,C: Phase 3 — Resume from checkpoint with CORRUPT TOKEN

    H->>H: cursor₁'' = Cursor::with_token(cursor₁.last_key, random_bytes)
    H->>C: enumerate_page(shard, cursor₁'', budgets)
    Note over C: Token decode fails →<br/>fall back to key_resume_start()
    C-->>H: page₂'' {items must match baseline suffix}

    Note over H,C: Phase 4 — Verification
    H->>H: Assert page₂.items == page₂'.items == page₂''.items<br/>(element-by-element digest comparison)
```

---

## 5. Cursor Construction

After emitting a page of items, each connector builds the continuation cursor
using shared helpers in `common.rs`. The process varies slightly between the
streaming filesystem connector (which encodes DFS stack state) and the
index-based connectors (git, in-memory) that encode a simple array offset.

For index-based connectors, `build_next_cursor()` encodes `next_idx` (the index
of the first un-emitted item) as an 8-byte big-endian `u64` token. The
`build_next_cursor_from_staged()` variant reuses a pre-staged pooled token when
one was already allocated during page assembly, avoiding a redundant allocation.

For the filesystem connector, `build_next_walk_cursor()` serializes the current
`WalkState` stack into a `WalkToken` via `WalkToken::encode_from_state()`. Token
construction failure (for example, when the encoded size exceeds `MAX_TOKEN_SIZE`)
gracefully degrades to a key-only cursor.

When the data source is exhausted (no more items to emit), the connector returns
`Cursor::initial()` — signalling that the shard is complete. An empty page with a
non-initial cursor signals "no items in this range, but more data may exist beyond."

```mermaid
%% Diagram: cursor-construction
graph TD
    subgraph page_emission["Page Emission"]
        ITEMS["Emit items[start_idx .. start_idx + take]"]
        LAST["last_key = items.last().item_key()"]
    end

    subgraph index_path["Index-Based Path (Git / InMemory)"]
        NEXT_IDX["next_idx = start_idx + take"]
        ENCODE["token = u64(next_idx).to_be_bytes()"]
        TOKEN_BYTES["TokenBytes::try_from_slice(&token)"]
        BUILD["Cursor::with_token(last_key, token)"]
    end

    subgraph fs_path["Filesystem Path"]
        WALK_STATE["WalkState { stack, current_path, ... }"]
        WALK_ENCODE["WalkToken::encode_from_state(&state)<br/>version + frame_count + frames[]"]
        WALK_TOKEN["TokenBytes::try_from_vec(encoded)"]
        FS_BUILD["Cursor::with_token(last_key, walk_token)"]
    end

    subgraph no_token_path["Token Disabled / Encoding Failure"]
        KEY_ONLY["Cursor::with_last_key(last_key)"]
    end

    subgraph exhausted["Data Source Exhausted"]
        DONE["Return Cursor::initial()<br/>← signals shard complete"]
    end

    ITEMS --> LAST
    LAST -->|"emit_tokens = true<br/>(index-based)"| NEXT_IDX
    LAST -->|"emit_tokens = true<br/>(filesystem)"| WALK_STATE
    LAST -->|"emit_tokens = false"| KEY_ONLY

    NEXT_IDX --> ENCODE --> TOKEN_BYTES --> BUILD
    WALK_STATE --> WALK_ENCODE --> WALK_TOKEN --> FS_BUILD
    WALK_ENCODE -->|"encoding fails or<br/>exceeds MAX_TOKEN_SIZE"| KEY_ONLY

    style page_emission fill:none,stroke:#991B1B,stroke-width:1px
    style index_path fill:none,stroke:#991B1B,stroke-width:1px
    style fs_path fill:none,stroke:#991B1B,stroke-width:1px
    style no_token_path fill:none,stroke:#991B1B,stroke-width:1px
    style exhausted fill:none,stroke:#991B1B,stroke-width:1px

    style ITEMS fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style LAST fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style NEXT_IDX fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style ENCODE fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style TOKEN_BYTES fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style BUILD fill:#EF4444,stroke:#991B1B,stroke-width:2px,color:#FFFFFF
    style WALK_STATE fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style WALK_ENCODE fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style WALK_TOKEN fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style FS_BUILD fill:#EF4444,stroke:#991B1B,stroke-width:2px,color:#FFFFFF
    style KEY_ONLY fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style DONE fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
```

---

## Cross-References

| Topic | Diagram | Relevance |
|-------|---------|-----------|
| Connector boundary overview | [09-circuit-breaker.md](09-circuit-breaker.md) | B4 fault isolation context |
| Shard key ranges and splits | [12-split-operations.md](12-split-operations.md) | Shard bounds that constrain cursor ranges |
| Shard algebra types | [13-shard-algebra-types.md](13-shard-algebra-types.md) | `ShardSpec` key range encoding that cursors operate within |
| End-to-end scan flow | [04-end-to-end-scan-flow.md](04-end-to-end-scan-flow.md) | Where cursor resume fits in the 12-step scan sequence |
| Lease lifecycle | [07-lease-lifecycle.md](07-lease-lifecycle.md) | Cursor monotonicity enforcement by the coordination layer |

---

## Source Code References

| Symbol / Concept | File | Line(s) | Notes |
|-----------------|------|---------|-------|
| `Cursor` struct | `crates/gossip-contracts/src/connector/types.rs` | 592–595 | Two-field struct: `last_key` + `token` |
| `Cursor::initial()` | `crates/gossip-contracts/src/connector/types.rs` | 604–609 | No-progress neutral state |
| `Cursor::with_last_key()` | `crates/gossip-contracts/src/connector/types.rs` | 617–621 | Key-only cursor constructor |
| `Cursor::with_token()` | `crates/gossip-contracts/src/connector/types.rs` | 630–635 | Key + token cursor constructor |
| `Cursor::try_from_update()` | `crates/gossip-contracts/src/connector/types.rs` | 688–702 | Validates `TokenWithoutLastKey` invariant |
| `ItemKey` | `crates/gossip-contracts/src/connector/types.rs` | 512–530 | Ordered toxic-byte wrapper, max 4 KiB |
| `TokenBytes` | `crates/gossip-contracts/src/connector/types.rs` | 555–576 | Unordered toxic-byte wrapper, max 16 KiB |
| `key_resume_start()` | `crates/gossip-connectors/src/common.rs` | 202–210 | O(log N) key-authoritative resume position |
| `cursor_token_index()` | `crates/gossip-connectors/src/common.rs` | 271–276 | Decode u64 token as array index |
| `build_next_cursor()` | `crates/gossip-connectors/src/common.rs` | 289–303 | Encode next_idx as u64 BE token |
| `build_next_cursor_from_staged()` | `crates/gossip-connectors/src/common.rs` | 317–333 | Reuse pre-staged pooled token |
| `upper_bound()` | `crates/gossip-connectors/src/common.rs` | 126–128 | First index where key > target |
| `WalkToken` struct | `crates/gossip-connectors/src/filesystem.rs` | 230–232 | Serialized DFS stack checkpoint |
| `WalkTokenFrame` | `crates/gossip-connectors/src/filesystem.rs` | 234–244 | Per-frame component + child index |
| `WALK_TOKEN_VERSION` | `crates/gossip-connectors/src/filesystem.rs` | 219 | Version byte `0x01` |
| `WalkToken::decode_bytes()` | `crates/gossip-connectors/src/filesystem.rs` | 1270–1319 | Deserialize with validation |
| `WalkToken::encode_from_state()` | `crates/gossip-connectors/src/filesystem.rs` | 1321–1377 | Serialize walk stack with size truncation |
| `WalkState::from_token()` | `crates/gossip-connectors/src/filesystem.rs` | 1571–1702 | Restore DFS state from token |
| `align_walk_to_cursor()` | `crates/gossip-connectors/src/filesystem.rs` | 593–671 | Token-first, key-fallback resume |
| `build_next_walk_cursor()` | `crates/gossip-connectors/src/filesystem.rs` | 677–689 | Encode walk state into cursor token |
| Git token resume | `crates/gossip-connectors/src/git.rs` | 398–418 | O(1) token + key cross-check |
| `ResumeChecks` | `crates/gossip-contracts/src/connector/conformance.rs` | 151–156 | Drop-token and corrupt-token flags |
| `ResumeMode` | `crates/gossip-contracts/src/connector/conformance.rs` | 388–397 | `DropToken` and `CorruptToken` variants |
| `ConformanceConfig` | `crates/gossip-contracts/src/connector/conformance.rs` | 258–286 | Harness configuration with resume checks |
