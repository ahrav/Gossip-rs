# Persistence Identity Contracts

> **Status: Aspirational** — This document describes a planned persistence-layer
> identity system that has not been implemented. The types (`StoreKeys`,
> `RunModeMetadata`, `IdentityFlags`, `OccurrenceInput`, `VariantDiscriminant`)
> do not exist in the codebase. For the **implemented** identity system, see
> [boundary-1-identity-spine.md](boundary-1-identity-spine.md) which documents
> `FindingIdInputs`, `OccurrenceIdInputs`, and the BLAKE3-based derivation chain
> in `crates/gossip-contracts/src/identity/`.

Deterministic, versioned identity contracts for persistence across all
scanner sources. These contracts let the scanner answer "have I seen this
exact finding before?" across runs without storing raw secret bytes.

**Source**: `crates/scanner-scheduler/src/store.rs`

## Purpose

The detection engine emits `FindingRec` records during scanning. To support
cross-run deduplication, suppression, and incremental scanning, each finding
needs a **stable identity** that:

- Is deterministic: same inputs always produce the same ID.
- Is keyed: IDs are meaningless without the operator's secret key.
- Matches engine dedupe semantics: two findings the engine considers
  duplicates must hash to the same occurrence ID.
- Never stores raw secret bytes: only keyed hashes are persisted.
- Is source-agnostic: works for filesystem, Git, S3, archives, and any
  future source without contract changes.

This module provides the identity derivation contracts. Current integration
targets filesystem scanning, but the contracts are source-agnostic by
design.

## Source Agnosticism

The identity contracts are deliberately source-neutral. Every input to the
three derivation functions is either engine-provided (and therefore
source-independent) or caller-provided via a generic byte slice:

| Input                 | Type                         | Source-specific?                                           |
| --------------------- | ---------------------------- | ---------------------------------------------------------- |
| `object_key`          | `&[u8]`                      | No — caller provides any stable byte ID                    |
| `FindingRec` fields   | buffer offsets (`u32`/`u64`) | No — engine produces these for all sources                 |
| `norm_hash`           | `[u8; 32]`                   | No — engine computes this on the hot path for every source |
| `StoreKeys`           | env var + KDF                | No — per-process, not per-source                           |
| `VariantDiscriminant` | encoding variant             | No — engine-level concept                                  |

The `object_key` field is the source abstraction point. Its doc comment
reads "stable object identity bytes **(e.g.** a canonical repo-relative
path)" — the "e.g." is intentional. Any stable byte representation works.

### How Each Source Provides object_key

| Source     | Example `object_key`                   | Stability guarantee               |
| ---------- | -------------------------------------- | --------------------------------- |
| Filesystem | `fs:crates/scanner-rs-cli/src/main.rs` | Repo-relative path (not absolute) |
| Git        | `git:<repo-id>:<blob-oid>`             | Blob OID is content-addressed     |
| S3         | `s3://<bucket>/<key>@<version-id>`     | Version ID is immutable           |
| Archive    | `tar:<archive-path>:<entry-path>`      | Entry path within archive         |
| Log        | `log:<source-id>:<line-range>`         | Source + position                 |

**Collision safety**: `object_key` values must be globally unambiguous across
sources. Using a scheme prefix (e.g. `fs:`, `git:`, `s3:`) prevents
cross-source collisions. The contracts do not enforce a prefix — this is a
caller responsibility.

### What Future Sources Need

To use the identity contracts, a new source needs:

1. A canonical `object_key` byte representation (defined by the source driver).
2. A `FindingRec` — the engine already produces this for any byte buffer.
3. `norm_hash` — the engine already computes this during scanning.

Zero changes to `identity.rs` or `keys.rs` are required.

### SourceKind and Occurrence ID

The codebase has `SourceKind { Fs, Git }` in `crates/scanner-scheduler/src/source_kind.rs` for event
routing. This enum is **not** part of the `occurrence_id` payload. Source
identity flows through the `object_key`, not a separate discriminator field.
This is intentional: adding a `SourceKind` field to the canonical payload
would require a version bump and would not add value if `object_key` schemes
are already unambiguous.

## Relationship to Git Persistence

Git scanning (`crates/scanner-git/src/persist.rs`) has its own persistence pipeline
that uses `(start, end, rule_id, norm_hash)` as finding keys and writes
through a two-phase contract (data ops then watermarks).

The `crates/scanner-scheduler/src/store/` module is a **separate, parallel identity system** that
currently targets FS scanning (Phases B-E) but can serve Git and other
sources. The two systems share the same `norm_hash` concept (BLAKE3 of
secret bytes) but differ in scope:

| Aspect                | Git persistence                      | Store identity contracts              |
| --------------------- | ------------------------------------ | ------------------------------------- |
| Location              | `crates/scanner-git/src/persist.rs`  | `crates/scanner-scheduler/src/store/` |
| Finding key           | `(start, end, rule_id, norm_hash)`   | `occurrence_id` (32-byte keyed hash)  |
| Key material          | None (hashes are unkeyed)            | `SCANNER_SECRET_KEY` with KDF         |
| Cross-run correlation | Via ref watermarks + seen-blob store | Via persistent key identity           |
| Secret protection     | `norm_hash` is unkeyed BLAKE3        | `secret_hash` is keyed BLAKE3         |
| Source scope          | Git only                             | Any source                            |

The `occurrence_id` contract is a strict superset of Git's current dedup
key. Git could adopt `occurrence_id` to gain keyed hashing and stronger
identity guarantees without breaking its existing pipeline. The
`norm_hash` that Git already computes feeds directly into `secret_hash`.

## Key Bootstrap

```mermaid
flowchart TB
    subgraph EnvCheck["Environment Check"]
        Env["SCANNER_SECRET_KEY<br/>(base64, 32 bytes)"]
        Check{{"Present and valid?"}}
    end

    subgraph Persistent["Persistent Mode"]
        Decode["base64 decode → root_key"]
        PMeta["RunModeMetadata {<br/>  correlation: Persistent,<br/>  key_source: EnvVar<br/>}"]
    end

    subgraph Ephemeral["Ephemeral Fallback"]
        URand["/dev/urandom<br/>(or entropy-mixing fallback)"]
        EMeta["RunModeMetadata {<br/>  correlation: Ephemeral,<br/>  key_source: MissingEnvVar | InvalidEnvVar<br/>}"]
    end

    subgraph KDF["BLAKE3 Key Derivation"]
        IK["identity_key<br/>context: scanner.store.keys.v1.identity"]
        SK["secret_key<br/>context: scanner.store.keys.v1.secret"]
        MK["metadata_key<br/>context: scanner.store.keys.v1.metadata"]
    end

    Env --> Check
    Check -->|"yes"| Decode
    Check -->|"no / invalid"| URand

    Decode --> PMeta
    URand --> EMeta

    PMeta --> KDF
    EMeta --> KDF
    KDF --> IK
    KDF --> SK
    KDF --> MK

    style EnvCheck fill:#e3f2fd
    style Persistent fill:#e8f5e9
    style Ephemeral fill:#fff3e0
    style KDF fill:#f3e5f5
```

### Why BLAKE3 KDF?

`blake3::derive_key` is purpose-built for deriving independent subkeys from
a single root. Unlike `new_keyed` (which is a PRF/MAC), `derive_key` accepts
an arbitrary-length context string as domain separator. Each subkey's context
string ensures cryptographic independence even though all three share the
same root material. This avoids the need for HKDF or a separate KDF library.

### Persistent vs. Ephemeral Mode

| Mode           | When                               | Cross-run correlation   | Use case                                 |
| -------------- | ---------------------------------- | ----------------------- | ---------------------------------------- |
| **Persistent** | `SCANNER_SECRET_KEY` set and valid | Yes                     | Production: suppression, dedup, tracking |
| **Ephemeral**  | Env var missing or invalid         | No (process-local only) | CI/one-shot scans, development           |

`RunModeMetadata` is attached to `StoreKeys` so downstream consumers can
check `is_persistent()` and avoid assuming cross-run correlation when
the key is ephemeral.

### Generating a Key

```bash
# Generate a 32-byte random key, base64-encoded
head -c 32 /dev/urandom | base64
# Export for the scanner
export SCANNER_SECRET_KEY="<output from above>"
```

## Identity Contracts

All three contracts follow the same pattern:

1. Build a canonical byte payload from the input fields.
2. Feed the payload through a domain-separated BLAKE3 keyed hash.

```
H_key(domain ‖ NUL ‖ payload) → [u8; 32]
```

The NUL byte between domain and payload prevents ambiguity when one domain
string is a prefix of another (e.g. `"foo"` vs `"foobar"`).

### Contract 1: Rule Fingerprint

Stable per-rule identity derived from `RuleSpec::encode_policy()`.

```mermaid
flowchart LR
    subgraph Input["Input"]
        Rule["RuleSpec"]
        Encode["encode_policy()<br/>(deterministic, order-invariant)"]
    end

    subgraph Hash["Unkeyed Hash"]
        Domain["domain: scanner.store.identity.v1.rule_fingerprint"]
        Key["(unkeyed — must be comparable across operators)"]
        BLAKE3["BLAKE3 hash"]
    end

    Output["RuleFingerprint<br/>[u8; 32]"]

    Rule --> Encode
    Encode --> BLAKE3
    Domain --> BLAKE3
    Key --> BLAKE3
    BLAKE3 --> Output

    style Input fill:#e3f2fd
    style Hash fill:#fff3e0
```

`encode_policy()` sorts and deduplicates anchors and keywords before
encoding, so the fingerprint is order-invariant. Two `RuleSpec` values
with identical detection semantics always produce the same fingerprint.

### Contract 2: Secret Hash

Keyed hash over the engine's pre-computed `norm_hash`.

```mermaid
flowchart LR
    subgraph Input["Input"]
        NormHash["norm_hash<br/>(BLAKE3 of secret bytes,<br/>already computed on hot path)"]
    end

    subgraph Hash["Keyed Hash"]
        Domain["domain: scanner.store.identity.v1.secret_hash"]
        Key["key: secret_key"]
        BLAKE3["BLAKE3 keyed hash"]
    end

    Output["SecretHash<br/>[u8; 32]"]

    NormHash --> BLAKE3
    Domain --> BLAKE3
    Key --> BLAKE3
    BLAKE3 --> Output

    style Input fill:#e3f2fd
    style Hash fill:#fff3e0
```

The engine already computes `norm_hash = BLAKE3(secret_bytes)` during
scanning. `secret_hash` wraps this with a keyed domain hash so that:

- The persisted hash is meaningless without the operator's key.
- No hot-path recomputation is needed; the existing `norm_hash` is reused.

### Contract 3: Occurrence ID

Canonical finding identity that mirrors engine dedupe semantics.

```mermaid
flowchart TB
    subgraph Inputs["Inputs"]
        ObjectKey["object_key<br/>(canonical path, e.g. repo:crates/scanner-rs-cli/src/main.rs)"]
        Finding["FindingRec<br/>(span, root_hint, step_id, dedupe_with_span)"]
        RuleFP["RuleFingerprint<br/>(from contract 1)"]
        SecHash["SecretHash<br/>(from contract 2)"]
        Variant["VariantDiscriminant<br/>(None / Utf16Le / Utf16Be)"]
    end

    subgraph Normalize["Canonicalize"]
        Flags["Compute IdentityFlags"]
        SpanErase["Zero span if non-root + !dedupe_with_span"]
        PadNorm["Normalize root_hint_end<br/>(base64 padding tolerance)"]
    end

    subgraph Encode["Canonical Payload"]
        Header["occurrence_canonical\\0 + version"]
        FlagsEnc["flags (u32 LE)"]
        ObjEnc["object_key (len-prefixed)"]
        RFPEnc["rule_fingerprint (32 bytes)"]
        SHEnc["secret_hash (32 bytes)"]
        SpanEnc["span_start + span_end (u32 LE)"]
        RHEnc["root_hint_start + root_hint_end (u64 LE)"]
        VarEnc["variant (u8)"]
    end

    subgraph Hash["Keyed Hash"]
        Domain["domain: scanner.store.identity.v1.occurrence_id"]
        Key["key: identity_key"]
        BLAKE3["BLAKE3 keyed hash"]
    end

    Output["OccurrenceId<br/>[u8; 32]"]

    Inputs --> Normalize
    Normalize --> Encode
    Encode --> BLAKE3
    Domain --> BLAKE3
    Key --> BLAKE3
    BLAKE3 --> Output

    style Inputs fill:#e3f2fd
    style Normalize fill:#ffebee
    style Encode fill:#e8f5e9
    style Hash fill:#fff3e0
```

## Normalization Rules

Occurrence ID must produce identical hashes for findings the engine already
considers duplicates. Two normalizations handle the tricky cases.

### Base64 Padding Tolerance

Base64 encodes 3 raw bytes into 4 encoded characters. When the raw length
is not a multiple of 3, the encoder may append 1-3 `=` padding characters.
Different implementations may or may not include padding, causing
`root_hint_end` to vary for identical decoded content.

```
Decoded length: 13 bytes
Minimum encoded: ceil(13 * 4 / 3) = 18 characters

  No padding:    root_hint_end = start + 18   ─┐
  With padding:  root_hint_end = start + 19..21 ├─ same decoded content
                                                ─┘
  Solution: if actual_encoded ∈ [min+1, min+3],
            snap root_hint_end to start + min
```

This normalization applies only to non-root findings (transform-derived).
Root findings use authoritative spans and are left untouched.

### Non-Root Span Erasure

For transform-derived findings, the decoded-buffer span (`span_start`,
`span_end`) shifts with chunk alignment. Two scan runs that process
the same file with different chunk boundaries will produce different
span offsets for the same logical secret.

```
Chunk A alignment:  span = [100..116]  ─┐  same secret,
Chunk B alignment:  span = [900..916]  ─┘  different offsets

Solution: zero span_start and span_end for non-root findings
          unless dedupe_with_span is true.
          Only the root-hint window participates in identity.
```

### UTF-16 Variant Discrimination

The engine discovers the same secret in raw bytes and again inside UTF-16
LE or BE re-encodings of the same region. Each encoding produces a distinct
finding that must hash to a distinct occurrence ID. The `VariantDiscriminant`
is included in the canonical payload:

| Value | Meaning                                         |
| ----- | ----------------------------------------------- |
| `0`   | No UTF-16 variant (root or non-UTF16 transform) |
| `1`   | UTF-16 little-endian                            |
| `2`   | UTF-16 big-endian                               |

**Invariant**: root-step findings (`step_id == STEP_ROOT`) must always use
variant `None`. A root finding with a UTF-16 variant is rejected as a caller
bug.

## Identity Flags

Rather than encoding boolean properties implicitly via which payload fields
are zero, `IdentityFlags` makes every semantic dimension explicit and
machine-checkable.

```
Bit layout (u32 LE):

  bit 0    FLAG_ROOT_STEP                  — finding is from the root buffer
  bit 1    FLAG_SPAN_INCLUDED              — decoded-buffer span participates in identity
  bit 2    FLAG_ROOT_HINT_END_NORMALIZED   — root_hint_end was padding-normalized
  bits 3-7   (reserved, must be zero)
  bit 8    FLAG_UTF16_LE                   — UTF-16 LE variant
  bit 9    FLAG_UTF16_BE                   — UTF-16 BE variant
  bits 10-31  (reserved, must be zero)
```

Validation rules:
- Unknown bits (any reserved bit set) are rejected.
- Bits 8 and 9 are mutually exclusive; setting both is rejected.
- `from_bits_strict()` enforces these invariants at construction time.

## Versioning

`IDENTITY_CONTRACT_VERSION` (currently `1`) is embedded in every canonical
payload. The version byte is the first thing after the payload header, so
old and new hashes can never collide silently.

**When to bump the version**:
- Any change to the canonical encoding format (field order, width, tags).
- Any change to normalization rules (padding tolerance window, span erasure logic).
- Any change to flag layout (new bits, reinterpreted bits).
- Any change to the domain strings or key derivation contexts.

**What does NOT require a bump**:
- Adding new test cases.
- Refactoring internal code that preserves the same byte output.
- Changes to non-identity fields in `FindingRec` (e.g. `file_id`).

## Domain Separation Summary

| Contract         | Domain String                                | Key            |
| ---------------- | -------------------------------------------- | -------------- |
| Rule fingerprint | `scanner.store.identity.v1.rule_fingerprint` | _(unkeyed)_    |
| Secret hash      | `scanner.store.identity.v1.secret_hash`      | `secret_key`   |
| Occurrence ID    | `scanner.store.identity.v1.occurrence_id`    | `identity_key` |

Domain separation ensures identical byte payloads in different contexts
produce distinct hashes. For example, a rule fingerprint and an occurrence
ID with the same byte content will never collide because they use different
domain strings.

## Memory and Performance

- **Key bootstrap**: runs once at startup, off the hot path. Three BLAKE3
  `derive_key` calls plus one base64 decode (or `/dev/urandom` read).
- **Rule fingerprint**: computed once per rule at engine build time.
- **Secret hash**: reuses the engine's existing `norm_hash` (no raw-secret
  rehash on the hot path).
- **Occurrence ID**: one `Vec` allocation for the canonical payload
  (typically <300 bytes), one BLAKE3 keyed hash. Expected to be called
  at finding-materialization time, not in the per-chunk scan loop.

## Related Documentation

| Document                                                                      | Relevance                                                                                                   |
| ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| [fs-persistence-pipeline.md](../scanner-scheduler/fs-persistence-pipeline.md) | FS persistence pipeline (StoreProducer, SQLite backend, loss accounting)                                    |
| [detection-engine.md](../scanner-engine/detection-engine.md)                  | FindingRec output, norm_hash computation                                                                    |
| [transform-chain.md](../scanner-engine/transform-chain.md)                    | Identity canonicalization link for transforms                                                               |
| [memory-management.md](../memory-management.md)                               | Store key bootstrap memory notes                                                                            |
| [git-scanning.md](../scanner-git/git-scanning.md)                             | Git persistence pipeline (separate system)                                                                  |
| [data-types.md](../data-types.md)                                             | StoreKeys, IdentityFlags, OccurrenceInput class diagrams *(aspirational — these types are not implemented)* |
| [architecture-overview.md](../architecture-overview.md)                       | Component table entries for Store Keys / Store Identity                                                     |
