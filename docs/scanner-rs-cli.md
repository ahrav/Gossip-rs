# scanner-rs-cli

## 1. Module Purpose

The `scanner-rs-cli` crate is the **standalone command-line binary** for
the gossip-rs secret scanning system. It produces the `scanner-rs`
executable that provides filesystem and git repository secret scanning
from the terminal with configurable output formats.

The crate is an intentionally **thin shell** of `main.rs`
that delegates all real work to `gossip-scanner-runtime`. Its sole
responsibilities are:

1. Invoking argument parsing (`gossip_scanner_runtime::cli::parse_args()`)
2. Invoking scan execution (`gossip_scanner_runtime::cli::run(config)`)
3. Handling process-exit policy: printing help to stdout, errors to
   stderr, and setting exit codes
4. Printing the full causal error chain via `print_error_chain` (walks
   `Error::source()` to display nested causes)

This separation is explicit: *"Process-exit policy is intentionally
handled in this binary while `gossip-scanner-runtime` returns typed
errors."*

---

## 2. Source File Map

| File | Purpose |
|------|---------|
| `src/main.rs` | Binary entrypoint: parse, dispatch, exit, error-chain printing |
| `Cargo.toml` | Manifest: single dependency on `gossip-scanner-runtime` |

There is no `lib.rs`, no additional modules, and no subdirectories.

---

## 3. Architecture

```text
scanner-rs-cli (Tier 3 binary, produces `scanner-rs`)
  --> gossip-scanner-runtime (Tier 2: all CLI logic lives here)
       --> gossip-contracts       (source-family contracts, coordination + identity types)
       --> scanner-engine          (detection pipeline)
       --> scanner-scheduler       (execution scheduling, FS scanning)
       --> scanner-git             (git repository scanning)

```

The canonical source-boundary guide lives in `docs/source-families.md`.

### Execution flow

```text
scanner-rs scan {fs|git} [OPTIONS]

main()
  |
  +--> parse_args()
  |     |
  |     +--> Ok(config) --> run(config)
  |     |                      |
  |     |                      +--> Ok(_) --> exit 0
  |     |                      |
  |     |                      +--> Err(e) --> print_error_chain(&e) --> exit 2
  |     |
  |     +--> Err(HelpRequested(usage)) --> println!("{usage}") --> exit 0
  |     |
  |     +--> Err(error) --> print_error_chain(&error) --> exit 2
```

### Exit codes

| Code | Meaning |
|:----:|---------|
| 0 | Scan completed successfully, or `--help` requested |
| 2 | Argument parsing error or scan execution failure |

---

## 4. CLI Grammar

```text
scanner-rs scan fs  --path <dir|file> [FS OPTIONS] [COMMON OPTIONS]
scanner-rs scan git --repo <path>     [GIT OPTIONS] [COMMON OPTIONS]
```

### Common flags

| Flag | Values | Default | Purpose |
|------|--------|---------|---------|
| `--execution-mode` | `direct`, `connector` | `direct` | Execution mode |
| `--max-items` | integer | 4096 | Checkpoint frequency |
| `--max-bytes` | integer | 67108864 (64 MiB) | Byte budget |
| `--workers` | integer >= 1 | runtime-selected | Worker threads |
| `--decode-depth` | integer | engine default | Max transform decode depth |
| `--anchors` | `manual`, `derived` | `manual` | Anchor extraction mode |
| `--rules` | file path | built-in | Custom YAML rules file |
| `--transforms` | `all`, `none`, `<csv>` | `all` | Transform filter (e.g., `url,base64`) |
| `--event-format` | `jsonl`, `text`, `json`, `sarif` | `jsonl` | Output format |
| `--null-sink` | flag | off | Drop all events (benchmarking) |
| `--verbose` | flag | off | Verbose text output |
| `--debug` | flag | off | Include extended debug/timing fields in the stderr summary |

### FS-specific flags

| Flag | Purpose |
|------|---------|
| `--path` | Path to scan (also accepted positionally) |
| `--skip-archives` / `--scan-archives` | Toggle archive expansion |
| `--scan-binary` / `--skip-binary` | Toggle binary file scanning |
| `--persist-findings` | Persist findings via commit bridge |

### Git-specific flags

| Flag | Purpose |
|------|---------|
| `--repo` | Repository path (also accepted positionally) |
| `--scan-binary` / `--skip-binary` | Toggle binary blob scanning |
| `--debug`, `--debug=stats`, `--debug=perf` | Debug output to stderr (stats or perf) |
| `--enrich-identities` | Emit identity dictionary |

### Git hidden flags (parsed but excluded from `--help`)

| Flag | Purpose |
|------|---------|
| `--x-repo-id` | Stable repository identifier |
| `--x-mode` | Scan mode: `diff`, `diff-history`, `odb-blob`, `odb-blob-fast` |
| `--x-merge` | Merge diff mode: `all`, `first-parent` |
| `--x-tree-delta-cache-mb` | Tree delta cache size in MiB |
| `--x-engine-chunk-mb` | Engine chunk size in MiB |

---

## 5. Key Types (from gossip-scanner-runtime)

The binary defines no types of its own. All types are imported from
`gossip_scanner_runtime::cli`:

### CliConfig

Builder-pattern configuration parsed from CLI arguments:

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `source` | `CliSource` | required | `Fs { path }` or `Git { repo }` |
| `execution_mode` | `ExecutionMode` | `Direct` | `Direct` or `Connector` |
| `budgets` | `ScanBudgets` | `{ 4096, 64 MiB }` | Checkpoint frequency and byte budget |
| `null_sink` | `bool` | `false` | Drop all events |
| `event_format` | `EventFormat` | `Jsonl` | Output format |
| `verbose` | `bool` | `false` | Verbose text output |
| `summary_debug` | `bool` | `false` | Append extended debug/timing fields to the stderr summary |
| `rules_file` | `Option<PathBuf>` | `None` | Custom YAML rules override |
| `transform_filter` | `TransformFilter` | `All` | Transform decoder filter |
| `workers` | `Option<usize>` | `None` | Worker thread count |
| `decode_depth` | `Option<usize>` | `None` | Max decode depth |
| `skip_archives` | `bool` | `false` | Skip archive expansion |
| `scan_binary` | `bool` | `false` | Scan binary files |
| `persist_findings` | `bool` | `false` | Persist via commit bridge |
| `anchor_mode` | `AnchorMode` | `Manual` | Anchor extraction mode |
| `debug_level` | `GitDebugLevel` | `Off` | Git debug output |
| `enrich_identities` | `bool` | `false` | Identity dictionary emission |
| `git_repo_id` | `u64` | `1` | Stable repo ID |
| `git_scan_mode` | `GitScanMode` | `OdbBlobFast` | Scan strategy |
| `git_merge_mode` | `MergeDiffMode` | `AllParents` | Merge diff strategy |
| `git_tree_delta_cache_mb` | `Option<u32>` | `None` | Delta cache size |
| `git_engine_chunk_mb` | `Option<u32>` | `None` | Engine chunk size |

### CliError

| Variant | Exit | Purpose |
|---------|:----:|---------|
| `HelpRequested(String)` | 0 | User asked for help |
| `Usage(String)` | 2 | Argument parsing error |
| `Runtime(ScanRuntimeError)` | 2 | Scan execution failure |

---

## 6. Dependencies

| Crate | Relationship |
|-------|-------------|
| `gossip-scanner-runtime` | **Only dependency.** Provides all CLI parsing, scan orchestration, and execution logic. |

### Feature Flags

| Feature | Effect |
|---------|--------|
| `aegis-pure-rust` | Cascades to `gossip-scanner-runtime/aegis-pure-rust` for pure-Rust engine |

---

## 7. Tests

The `scanner-rs-cli` crate itself contains **no tests** by design -- the
binary is a thin wrapper. All testing lives in `gossip-scanner-runtime`:

- **CLI parsing tests** (in `cli_tests.rs`): Flag parsing, CSV transform
  parsing, positional arguments, hidden flag exclusion, help text
- **Core wiring tests** (in `lib_tests.rs`): Execution mode
  parsing, FS/git scan dispatch, budget validation, direct/connector parity
- **Event sink tests** (in `event_sink.rs`): JSONL, text, JSON,
  SARIF encoding, double-flush safety
- **Parity tests** (in `parity.rs`): JSONL canonicalization for
  cross-scanner comparison

---

## 8. Relationship to gossip-worker

Both `scanner-rs-cli` and `gossip-worker` are top-level binaries that
route through the same family-oriented runtime boundary:

```text
config -> scan_fs / scan_git -> validation -> ordered_content / git_repo runtime boundary
```

| Aspect | scanner-rs-cli | gossip-worker |
|--------|---------------|---------------|
| Purpose | Interactive CLI | Distributed worker |
| Default mode | Direct | Connector |
| Output | Structured events to stdout | Tracing logs |
| Findings | Per-finding event stream | Summary only |
| Persistence | Optional (`--persist-findings`) | Planned via coordinator |
| CLI complexity | Rich (30+ flags) | Minimal (3 positionals) |

---

## 9. Source of Truth

| Concern | Path |
|---------|------|
| Binary entrypoint | `crates/scanner-rs-cli/src/main.rs` |
| CLI parsing and `run()` | `crates/gossip-scanner-runtime/src/cli.rs` |
| Scan orchestration | `crates/gossip-scanner-runtime/src/lib.rs` |
| Output format sinks | `crates/gossip-scanner-runtime/src/event_sink.rs` |
